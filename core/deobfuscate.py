from __future__ import annotations
import re
import json

WEBPACK_ARRAY_RE    = re.compile(r"""var\s+(_0x[a-f0-9]{4,8})\s*=\s*(\["[^;]{10,}?"\])\s*;""", re.DOTALL)
OB_ARRAY_RE         = re.compile(r"""var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(\['[^;]{20,}?'\])\s*;""", re.DOTALL)
STRING_ROTATION_RE  = re.compile(r"""_0x[a-f0-9]+\['push'\]\(_0x[a-f0-9]+\['shift'\]\(\)\)""")
NEXT_F_PUSH_RE      = re.compile(r"""self\.__next_f\.push\(\s*\[.*?,(["'])(.*?)\1\s*\]\s*\)""", re.DOTALL)
HEX_ESCAPE_RE       = re.compile(r"""\\x([0-9a-fA-F]{2})""")
UNICODE_ESCAPE_RE   = re.compile(r"""\\u([0-9a-fA-F]{4})""")
WEBPACK_MOD_RE      = re.compile(r"""__webpack_require__\.m\s*=\s*\{(.*?)\}""", re.DOTALL)
TERSER_STR_RE       = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{32,})['"]""")
OBFUSCATOR_CALL_RE  = re.compile(r"""_0x[a-f0-9]{4,8}\s*\(\s*0x[0-9a-f]+\s*,\s*['"][^'"]+['"]\s*\)""")
CHARCODE_RE         = re.compile(r"""String\.fromCharCode\(([0-9,\s]+)\)""")


def _decode_hex_escapes(s: str) -> str:
    def replace_hex(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)
    return HEX_ESCAPE_RE.sub(replace_hex, s)


def _decode_unicode_escapes(s: str) -> str:
    def replace_uni(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)
    return UNICODE_ESCAPE_RE.sub(replace_uni, s)


def _decode_charcodes(content: str) -> str:
    def replace_cc(m):
        try:
            codes = [int(c.strip()) for c in m.group(1).split(",")]
            return "'" + "".join(chr(c) for c in codes if 32 <= c < 127) + "'"
        except Exception:
            return m.group(0)
    return CHARCODE_RE.sub(replace_cc, content)


def _extract_string_arrays(content: str) -> list[str]:
    strings: list[str] = []
    for pattern in [WEBPACK_ARRAY_RE, OB_ARRAY_RE]:
        for m in pattern.finditer(content):
            raw = m.group(2)
            try:
                arr = json.loads(raw.replace("'", '"'))
                if isinstance(arr, list):
                    strings.extend(str(s) for s in arr if isinstance(s, str))
            except Exception:
                strings.extend(re.findall(r"""["']([^"']{4,})["']""", raw))
    return strings


def _extract_rsc_fragments(content: str) -> list[str]:
    return [m.group(2) for m in NEXT_F_PUSH_RE.finditer(content) if m.group(2)]


def is_obfuscated(content: str) -> bool:
    score = 0
    if re.search(r"_0x[a-f0-9]{4}", content):      score += 2
    if STRING_ROTATION_RE.search(content):           score += 2
    if content.count("\\x") > 50:                   score += 1
    if content.count("\\u00") > 30:                 score += 1
    if CHARCODE_RE.search(content):                  score += 1
    if OBFUSCATOR_CALL_RE.search(content):           score += 2
    if len(content) > 10000 and "\n" not in content[:5000]: score += 1
    return score >= 3


def is_nextjs(content: str) -> bool:
    return any(s in content for s in [
        "__NEXT_DATA__", "webpackChunk", "TURBOPACK", "__next_f",
        "_buildManifest", "_ssgManifest", "next/dist",
    ])


def deobfuscate(content: str) -> str:
    extra: list[str] = []

    content = _decode_hex_escapes(content)
    content = _decode_unicode_escapes(content)
    content = _decode_charcodes(content)

    if is_obfuscated(content):
        strings = _extract_string_arrays(content)
        if strings:
            extra.append(
                '\n/* [JSReaper:deobf-strings]\n'
                + "\n".join(f'"{s}"' for s in strings[:3000])
                + '\n*/'
            )

    rsc = _extract_rsc_fragments(content)
    if rsc:
        extra.append('\n/* [JSReaper:rsc-fragments]\n' + "\n".join(rsc[:500]) + '\n*/')

    return content + "".join(extra) if extra else content
