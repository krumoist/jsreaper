from __future__ import annotations
import re
import json
import base64
import hashlib
from urllib.parse import unquote
from .patterns import compile_patterns, SEVERITY_ORDER
from .entropy import find_high_entropy_strings
from .endpoints import extract_endpoints
from .deobfuscate import deobfuscate

CONF_ORDER = {"confirmed": 4, "likely": 3, "possible": 2, "unlikely": 1}

PLACEHOLDER_VALUES = frozenset({
    "", "null", "undefined", "none", "false", "true", "0", "1",
    "your_key_here", "your-key-here", "your_secret", "your-secret",
    "api_key_here", "replace_me", "changeme", "placeholder",
    "xxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxx", "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
})

ENV_RE = re.compile(r"process\.env\.|import\.meta\.env\.|os\.environ|getenv\(", re.I)

BASE64_CONTENT_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")

JSON_BLOB_RE = re.compile(r'\{(?:[^{}]|\{[^{}]*\}){20,500}\}')

URL_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _fingerprint(pattern: str, value: str) -> str:
    return hashlib.md5(f"{pattern}:{value}".encode()).hexdigest()


def _get_line_context(content: str, pos: int, lines: int = 3) -> dict:
    all_lines = content.splitlines()
    line_num  = content[:pos].count("\n")
    start     = max(0, line_num - lines)
    end       = min(len(all_lines), line_num + lines + 1)
    return {"line": line_num + 1, "context": "\n".join(all_lines[start:end])}


def _is_placeholder(value: str, context: str) -> bool:
    vl = value.lower().strip("'\"` ")
    if vl in PLACEHOLDER_VALUES:
        return True
    for hint in [
        "example", "placeholder", "your_", "your-", "xxx", "todo", "fixme",
        "replace", "changeme", "insert", "<key>", "<token>", "aaaaaaa",
        "11111111", "00000000", "test_key", "demo_key", "sample", "fake",
        "dummy", "mock", "stub",
    ]:
        if hint in vl:
            return True
    if len(set(value)) <= 3 and len(value) > 8:
        return True
    if ENV_RE.search(context):
        return True
    return False


def _extract_nested_secrets(content: str, source_url: str, compiled_patterns,
                             seen: set, context_lines: int = 0) -> list[dict]:
    nested: list[dict] = []

    for m in BASE64_CONTENT_RE.finditer(content):
        raw = m.group(0)
        try:
            decoded = base64.b64decode(raw + "==").decode("utf-8", errors="strict")
            if len(decoded) > 10 and decoded.isprintable():
                nested.extend(_scan_string(
                    decoded, f"{source_url} [base64]", compiled_patterns, seen, context_lines
                ))
        except Exception:
            pass

    for m in JSON_BLOB_RE.finditer(content):
        try:
            obj = json.loads(m.group(0))
            flat = json.dumps(obj)
            nested.extend(_scan_string(
                flat, f"{source_url} [json-blob]", compiled_patterns, seen, context_lines
            ))
        except Exception:
            pass

    if URL_ENCODED_RE.search(content):
        try:
            decoded = unquote(content)
            if decoded != content:
                nested.extend(_scan_string(
                    decoded, f"{source_url} [url-decoded]", compiled_patterns, seen, context_lines
                ))
        except Exception:
            pass

    return nested


def _scan_string(content: str, source_url: str, compiled_patterns,
                 seen: set, context_lines: int = 0) -> list[dict]:
    findings: list[dict] = []
    for pattern_def, regex in compiled_patterns:
        for match in regex.finditer(content):
            value = match.group(0)
            try:
                g1 = match.group(1)
                if g1:
                    value = g1
            except IndexError:
                pass
            value = value.strip()
            if len(value) < 4:
                continue
            ctx_start = max(0, match.start() - 120)
            ctx_end   = min(len(content), match.end() + 120)
            ctx_snip  = content[ctx_start:ctx_end]
            if _is_placeholder(value, ctx_snip):
                continue
            fp = _fingerprint(pattern_def["name"], value)
            if fp in seen:
                continue
            seen.add(fp)
            finding: dict = {
                "pattern":          pattern_def["name"],
                "severity":         pattern_def["severity"],
                "group":            pattern_def["group"],
                "value":            value,
                "source_url":       source_url,
                "line":             content[:match.start()].count("\n") + 1,
                "context":          None,
                "confidence_score": 70,
                "confidence_label": "likely",
            }
            if context_lines:
                loc = _get_line_context(content, match.start(), context_lines)
                finding["line"]    = loc["line"]
                finding["context"] = loc["context"]
            findings.append(finding)
    return findings


def _scan_nextdata_for_secrets(next_data: dict, source_url: str, compiled_patterns,
                                seen: set) -> list[dict]:
    try:
        flat = json.dumps(next_data)
    except Exception:
        return []
    findings = _scan_string(flat, f"{source_url} [__NEXT_DATA__]", compiled_patterns, seen)
    for f in findings:
        f["confidence_score"] = 75
    return findings


class Scanner:
    def __init__(self, args):
        self.args          = args
        self.compiled      = compile_patterns(
            disable=getattr(args, "disable_pattern", None),
            extra_file=getattr(args, "patterns", None),
        )
        self.entropy_on    = getattr(args, "entropy", False)
        self.entropy_thr   = getattr(args, "entropy_threshold", 4.0)
        self.min_len       = getattr(args, "min_secret_len", 16)
        self.show_ctx      = getattr(args, "show_context", False)
        self.ctx_lines     = getattr(args, "context_lines", 3)
        self.do_deobf      = getattr(args, "deobfuscate", False)
        self.secrets_only  = getattr(args, "secrets_only", False)
        self.endpoints_only= getattr(args, "endpoints_only", False)
        self.min_sev       = getattr(args, "severity", None)
        self.no_unique     = getattr(args, "no_unique", False)
        self.nested_scan   = getattr(args, "nested_scan", True)
        self.seen: set[str]= set()

    def _passes_severity(self, severity: str) -> bool:
        if not self.min_sev:
            return True
        from .patterns import SEVERITY_ORDER
        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(self.min_sev, 0)

    def scan_content(self, content: str, source_url: str, next_data: dict = None) -> dict:
        if self.do_deobf:
            content = deobfuscate(content)

        result: dict = {
            "source_url":       source_url,
            "secrets":          [],
            "endpoints":        {},
            "entropy_findings": [],
        }

        if not self.endpoints_only:
            seen = self.seen if not self.no_unique else set()
            filtered = [(p, r) for p, r in self.compiled if self._passes_severity(p["severity"])]

            primary = _scan_string(
                content, source_url, filtered, seen,
                self.ctx_lines if self.show_ctx else 0,
            )
            result["secrets"].extend(primary)

            if self.nested_scan:
                nested = _extract_nested_secrets(content, source_url, filtered, seen, 0)
                result["secrets"].extend(nested)

            if self.entropy_on:
                for ef in find_high_entropy_strings(content, self.entropy_thr, self.min_len):
                    fp = _fingerprint("entropy", ef["token"])
                    if fp not in seen:
                        seen.add(fp)
                        ef["source_url"] = source_url
                        result["entropy_findings"].append(ef)

        if not self.secrets_only:
            result["endpoints"] = extract_endpoints(content, source_url, next_data)

        return result

    def scan_inline_scripts(self, inline_scripts: list[str], page_url: str) -> dict:
        combined: dict = {
            "source_url":       f"{page_url} [inline]",
            "secrets":          [],
            "endpoints":        {},
            "entropy_findings": [],
        }
        for i, script in enumerate(inline_scripts):
            label = f"{page_url} [script #{i+1}]"
            res   = self.scan_content(script, label)
            combined["secrets"].extend(res["secrets"])
            combined["entropy_findings"].extend(res["entropy_findings"])
            for cat, items in res.get("endpoints", {}).items():
                existing = combined["endpoints"].get(cat, [])
                combined["endpoints"][cat] = sorted(set(existing) | set(items))
        return combined

    def scan_nextdata(self, next_data: dict, page_url: str) -> list[dict]:
        if self.endpoints_only:
            return []
        seen = self.seen if not self.no_unique else set()
        return _scan_nextdata_for_secrets(next_data, page_url, self.compiled, seen)

    def scan_rsc_payload(self, rsc_content: str, source_url: str) -> dict:
        frags = []
        for line in rsc_content.splitlines():
            colon = line.find(":")
            if colon > 0:
                data = line[colon + 1:].strip()
                if data.startswith(("{", "[", '"')):
                    frags.append(data)
        combined = "\n".join(frags) if frags else rsc_content
        return self.scan_content(combined, f"{source_url} [RSC]")
