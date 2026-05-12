from __future__ import annotations
import re
import json
import csv
import io
import sys

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[31m"
BRED    = "\033[91m"
GREEN   = "\033[32m"
BGREEN  = "\033[92m"
YELLOW  = "\033[33m"
BYELLOW = "\033[93m"
BLUE    = "\033[34m"
BBLUE   = "\033[94m"
CYAN    = "\033[36m"
BCYAN   = "\033[96m"
MAGENTA = "\033[35m"
BMAGENTA= "\033[95m"
WHITE   = "\033[97m"
GRAY    = "\033[90m"
BG_RED  = "\033[41m"
BG_DARK = "\033[40m"

SEV_THEME = {
    "critical": (BRED,    BG_RED, "◆ CRITICAL"),
    "high":     (BYELLOW, "",     "▲ HIGH    "),
    "medium":   (YELLOW,  "",     "● MEDIUM  "),
    "low":      (BCYAN,   "",     "○ LOW     "),
}
CONF_THEME = {
    "confirmed": (BGREEN,   "CONFIRMED"),
    "likely":    (GREEN,    "LIKELY   "),
    "possible":  (YELLOW,   "POSSIBLE "),
    "unlikely":  (GRAY,     "UNLIKELY "),
}

W = 90


def _c(nc: bool, *codes: str) -> str:
    return "" if nc else "".join(codes)


def _box_top(nc: bool, title: str = "") -> str:
    if nc:
        return f"\n{'=' * W}\n  {title}\n{'=' * W}"
    inner = f" {BOLD}{WHITE}{title}{RESET}{BBLUE} " if title else ""
    pad   = W - 4 - (len(title) + 2 if title else 0)
    return (f"\n{_c(nc, BBLUE)}╔{'═' * 2}{inner}{'═' * max(0, pad)}╗{_c(nc, RESET)}")


def _box_line(nc: bool, content: str = "", width: int = W) -> str:
    if nc:
        return f"  {content}"
    return f"{_c(nc, BBLUE)}║{_c(nc, RESET)}  {content}"


def _box_sep(nc: bool) -> str:
    if nc:
        return "─" * W
    return f"{_c(nc, BBLUE)}╠{'═' * (W - 2)}╣{_c(nc, RESET)}"


def _box_bot(nc: bool) -> str:
    if nc:
        return "=" * W
    return f"{_c(nc, BBLUE)}╚{'═' * (W - 2)}╝{_c(nc, RESET)}"


def _sev_badge(sev: str, nc: bool) -> str:
    col, bg, label = SEV_THEME.get(sev, (WHITE, "", sev.upper().ljust(10)))
    if nc:
        return f"[{label.strip()}]"
    return f"{bg}{col}{BOLD} {label} {RESET}"


def _conf_badge(conf: str, score: int, nc: bool) -> str:
    col, label = CONF_THEME.get(conf, (WHITE, conf.upper()))
    if nc:
        return f"[{label.strip()} {score}%]"
    return f"{col}{BOLD}[{label} {score:3d}%]{RESET}"


def _bar(count: int, max_w: int = 35, nc: bool = False) -> str:
    filled = min(count, max_w)
    over   = count > max_w
    bar    = "█" * filled + ("+" if over else "")
    if nc:
        return bar
    return f"{BMAGENTA}{bar}{RESET}"


BANNER = r"""
     ██╗███████╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
     ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
     ██║███████╗██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██   ██║╚════██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
╚█████╔╝███████║██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
 ╚════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝"""


def print_banner(target: str, nc: bool = False):
    if nc:
        print(f"\n  JSREAPER v3 :: JS Secret and Security Scanner")
        print(f"  Target: {target}\n")
        return
    print(f"{BRED}{BOLD}{BANNER}{RESET}")
    print(f"  {GRAY}{'─' * 66}{RESET}")
    print(f"  {BCYAN}{BOLD}JS Secret & Security Scanner{RESET}  {GRAY}|{RESET}  {WHITE}10x Elite Edition{RESET}  {GRAY}|{RESET}  {YELLOW}Red Team Ready{RESET}")
    print(f"  {GRAY}{'─' * 66}{RESET}")
    print(f"  {GRAY}Target  {RESET}{WHITE}{target}{RESET}")
    print()


def print_summary(results: dict, nc: bool = False):
    secrets   = results.get("secrets", [])
    issues    = results.get("security_issues", [])
    vuln_libs = results.get("vuln_libs", [])
    endpoints = results.get("endpoints", {})
    total_eps = sum(len(v) for v in endpoints.values())

    sev_counts: dict[str, int] = {}
    for f in secrets + issues + vuln_libs:
        s = f.get("severity", "low")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    print(_box_top(nc, "SCAN SUMMARY"))
    rows = [
        ("Target",             results.get("target", "")),
        ("Pages Visited",      str(results.get("pages_visited", 0))),
        ("JS Files Scanned",   str(results.get("js_files_scanned", 0))),
        ("Secrets Found",      str(len(secrets))),
        ("Security Issues",    str(len(issues))),
        ("Vulnerable Libs",    str(len(vuln_libs))),
        ("Endpoints Found",    str(total_eps)),
        ("Scan Start",         results.get("scan_start", "")),
        ("Scan End",           results.get("scan_end", "")),
    ]
    for k, v in rows:
        if nc:
            print(f"  {k:<22} {v}")
        else:
            print(f"{_c(nc, BBLUE)}║{RESET}  {CYAN}{k:<22}{RESET} {WHITE}{v}{RESET}")
    print(_box_sep(nc))
    for sev in ["critical", "high", "medium", "low"]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            badge = _sev_badge(sev, nc)
            bar   = _bar(cnt, 30, nc)
            cntstr= f"{WHITE}{cnt:>4}{RESET}" if not nc else str(cnt)
            if nc:
                print(f"  {sev.upper():<12} {cnt:>4}  {_bar(cnt, 30, nc=True)}")
            else:
                print(f"{_c(nc, BBLUE)}║{RESET}  {badge}  {cntstr}  {bar}")
    print(_box_bot(nc))

    group_counts: dict[str, int] = {}
    for f in secrets:
        g = f.get("group", "Other")
        group_counts[g] = group_counts.get(g, 0) + 1

    if group_counts:
        print(_box_top(nc, "SECRET CATEGORIES"))
        for grp, cnt in sorted(group_counts.items(), key=lambda x: -x[1])[:20]:
            bar = _bar(cnt, 28, nc)
            if nc:
                print(f"  {grp:<28} {cnt:>4}  {_bar(cnt, 28, nc=True)}")
            else:
                print(f"{_c(nc, BBLUE)}║{RESET}  {BCYAN}{grp:<28}{RESET}  {WHITE}{cnt:>4}{RESET}  {bar}")
        print(_box_bot(nc))


def print_secrets(secrets: list[dict], nc: bool = False, show_context: bool = False):
    if not secrets:
        return
    print(_box_top(nc, f"SECRETS  ◆  {len(secrets)} FOUND"))
    for idx, f in enumerate(secrets, 1):
        sev_b  = _sev_badge(f.get("severity", "low"), nc)
        conf_b = _conf_badge(f.get("confidence_label", "possible"), f.get("confidence_score", 0), nc)
        val    = f.get("value", "")
        mask   = val[:6] + "●●●●●●●●" + val[-3:] if len(val) > 14 else val
        grp    = f.get("group", "")
        src    = f.get("source_url", "")
        line   = f.get("line", "")
        if nc:
            print(f"\n  [{idx:03d}] {f.get('pattern','')}  {f.get('severity','').upper()}  {f.get('confidence_label','')}")
            print(f"  Pattern   {f.get('pattern','')}")
            print(f"  Group     {grp}")
            print(f"  Value     {mask}")
            print(f"  Source    {src}")
            print(f"  Line      {line}")
        else:
            print(f"{_c(nc, BBLUE)}╠{'═' * (W-2)}╣{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {GRAY}{idx:03d}{RESET}  {sev_b}  {conf_b}  {BOLD}{WHITE}{f.get('pattern','')}{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {GRAY}{'Group':<10}{RESET} {BCYAN}{grp}{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {GRAY}{'Value':<10}{RESET} {BRED}{BOLD}{mask}{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {GRAY}{'Source':<10}{RESET} {GRAY}{src}{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {GRAY}{'Line':<10}{RESET} {WHITE}{line}{RESET}")
        if show_context and f.get("context"):
            ctx_lines = f["context"].strip().splitlines()
            if nc:
                print(f"  Context:")
            else:
                print(f"{_c(nc, BBLUE)}║{RESET}  {GRAY}{'Context':<10}{RESET}")
            for cl in ctx_lines[:5]:
                cl_stripped = cl[:100]
                if nc:
                    print(f"    {cl_stripped}")
                else:
                    print(f"{_c(nc, BBLUE)}║{RESET}    {DIM}{cl_stripped}{RESET}")
    print(_box_bot(nc))


def print_security_issues(issues: list[dict], nc: bool = False):
    if not issues:
        return
    cat_groups: dict[str, list] = {}
    for f in issues:
        cat = f.get("category", f.get("group", "Other"))
        cat_groups.setdefault(cat, []).append(f)

    print(_box_top(nc, f"SECURITY ISSUES  ◆  {len(issues)} FOUND"))
    for cat, items in sorted(cat_groups.items()):
        if nc:
            print(f"\n  ► {cat} ({len(items)})")
        else:
            print(f"{_c(nc, BBLUE)}╠{'═' * (W-2)}╣{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {BYELLOW}{BOLD}► {cat}{RESET}  {GRAY}({len(items)} findings){RESET}")
        for f in items:
            sev_b = _sev_badge(f.get("severity", "low"), nc)
            if nc:
                print(f"    {f.get('pattern','')}  Line {f.get('line','')}")
                print(f"    {f.get('description','')}")
                print(f"    {f.get('source_url','')}")
            else:
                print(f"{_c(nc, BBLUE)}║{RESET}    {sev_b}  {WHITE}{f.get('pattern','')}{RESET}  {GRAY}line {f.get('line','')}{RESET}")
                print(f"{_c(nc, BBLUE)}║{RESET}         {DIM}{f.get('description','')[:80]}{RESET}")
                print(f"{_c(nc, BBLUE)}║{RESET}         {GRAY}{f.get('source_url','')[:80]}{RESET}")
    print(_box_bot(nc))


def print_vuln_libs(vuln_libs: list[dict], nc: bool = False):
    if not vuln_libs:
        return
    print(_box_top(nc, f"VULNERABLE LIBRARIES  ◆  {len(vuln_libs)} FOUND"))
    for f in vuln_libs:
        sev_b = _sev_badge(f.get("severity", "low"), nc)
        cves  = "  ".join(f.get("cves", []))
        if nc:
            print(f"\n  {f.get('value','')}  fix: {f.get('fix_version','?')}")
            print(f"  CVEs   {cves}")
            print(f"  Desc   {f.get('description','')}")
            print(f"  CVSS   {f.get('cvss_max','?')}")
        else:
            print(f"{_c(nc, BBLUE)}╠{'═' * (W-2)}╣{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {sev_b}  {BOLD}{WHITE}{f.get('value','')}{RESET}  {GRAY}fix:{RESET} {BGREEN}{f.get('fix_version','?')}{RESET}  {GRAY}CVSS {f.get('cvss_max','?')}{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {GRAY}{'CVEs':<10}{RESET} {BRED}{cves}{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {GRAY}{'Desc':<10}{RESET} {DIM}{f.get('description','')[:80]}{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {GRAY}{'Source':<10}{RESET} {GRAY}{f.get('source_url','')[:70]}{RESET}")
    print(_box_bot(nc))


def print_endpoints(endpoints: dict, nc: bool = False):
    total = sum(len(v) for v in endpoints.values())
    if not total:
        return
    print(_box_top(nc, f"ENDPOINTS  ◆  {total} TOTAL"))
    for cat, items in sorted(endpoints.items()):
        if not items:
            continue
        label = cat.replace("_", " ").upper()
        if nc:
            print(f"\n  ► {label} ({len(items)})")
        else:
            print(f"{_c(nc, BBLUE)}╠{'═' * (W-2)}╣{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {BCYAN}{BOLD}► {label}{RESET}  {GRAY}({len(items)}){RESET}")
        for item in items[:40]:
            if nc:
                print(f"    {item}")
            else:
                print(f"{_c(nc, BBLUE)}║{RESET}    {WHITE}{item[:84]}{RESET}")
        if len(items) > 40:
            more = len(items) - 40
            if nc:
                print(f"    ... and {more} more")
            else:
                print(f"{_c(nc, BBLUE)}║{RESET}    {GRAY}... and {more} more{RESET}")
    print(_box_bot(nc))


def print_intel(intel: dict, nc: bool = False):
    subs = intel.get("subdomains", [])
    js   = intel.get("js_urls", [])
    gh   = intel.get("github_hits", [])
    if not (subs or js or gh):
        return
    print(_box_top(nc, "OSINT INTELLIGENCE"))
    if subs:
        if nc:
            print(f"\n  Subdomains ({len(subs)})")
        else:
            print(f"{_c(nc, BBLUE)}╠{'═' * (W-2)}╣{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {BMAGENTA}{BOLD}SUBDOMAINS{RESET}  {GRAY}({len(subs)} found){RESET}")
        for s in subs[:30]:
            if nc: print(f"    {s}")
            else:  print(f"{_c(nc, BBLUE)}║{RESET}    {CYAN}{s}{RESET}")
        if len(subs) > 30:
            if nc: print(f"    ... and {len(subs) - 30} more")
            else:  print(f"{_c(nc, BBLUE)}║{RESET}    {GRAY}... and {len(subs) - 30} more{RESET}")
    if js:
        if nc:
            print(f"\n  Historical JS URLs ({len(js)})")
        else:
            print(f"{_c(nc, BBLUE)}╠{'═' * (W-2)}╣{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {BMAGENTA}{BOLD}HISTORICAL JS URLS{RESET}  {GRAY}({len(js)} found){RESET}")
        for u in js[:15]:
            if nc: print(f"    {u}")
            else:  print(f"{_c(nc, BBLUE)}║{RESET}    {GRAY}{u[:84]}{RESET}")
    if gh:
        if nc:
            print(f"\n  GitHub Code Search Hits ({len(gh)})")
        else:
            print(f"{_c(nc, BBLUE)}╠{'═' * (W-2)}╣{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {BMAGENTA}{BOLD}GITHUB CODE SEARCH HITS{RESET}  {GRAY}({len(gh)}){RESET}")
        for u in gh[:10]:
            if nc: print(f"    {u}")
            else:  print(f"{_c(nc, BBLUE)}║{RESET}    {WHITE}{u[:84]}{RESET}")
    print(_box_bot(nc))


def print_extraction(extraction: dict, nc: bool = False):
    interesting = {k: v for k, v in extraction.items() if v and k not in ("version_numbers",)}
    if not interesting:
        return
    print(_box_top(nc, "EXTRACTED INTEL"))
    for key, items in interesting.items():
        label = key.replace("_", " ").upper()
        if nc:
            print(f"\n  ► {label} ({len(items)})")
        else:
            print(f"{_c(nc, BBLUE)}╠{'═' * (W-2)}╣{RESET}")
            print(f"{_c(nc, BBLUE)}║{RESET}  {BCYAN}{BOLD}► {label}{RESET}  {GRAY}({len(items)}){RESET}")
        for item in items[:18]:
            display = str(item)[:86]
            if nc: print(f"    {display}")
            else:  print(f"{_c(nc, BBLUE)}║{RESET}    {WHITE}{display}{RESET}")
        if len(items) > 18:
            if nc: print(f"    ... and {len(items) - 18} more")
            else:  print(f"{_c(nc, BBLUE)}║{RESET}    {GRAY}... and {len(items) - 18} more{RESET}")
    print(_box_bot(nc))


def print_probe_results(probes: list[dict], nc: bool = False):
    if not probes:
        return
    print(_box_top(nc, f"ENDPOINT PROBE RESULTS  ◆  {len(probes)} LIVE"))
    for p in probes[:50]:
        status = p.get("status", 0)
        scol   = BGREEN if status < 300 else (BYELLOW if status < 400 else BRED)
        cors   = p.get("access_control", "")
        server = p.get("server", "")
        powered= p.get("x_powered_by", "")
        info   = "  ".join(filter(None, [
            f"Server: {server}" if server else "",
            f"Powered: {powered}" if powered else "",
            f"CORS: {cors}" if cors else "",
        ]))
        if nc:
            print(f"  [{status}]  {p.get('url','')}")
            if info: print(f"        {info}")
        else:
            print(f"{_c(nc, BBLUE)}║{RESET}  {scol}[{status}]{RESET}  {WHITE}{p.get('url','')[:72]}{RESET}")
            if info:
                print(f"{_c(nc, BBLUE)}║{RESET}        {GRAY}{info[:80]}{RESET}")
    print(_box_bot(nc))


def format_json(results: dict, pretty: bool = True) -> str:
    return json.dumps(results, indent=2 if pretty else None, default=str)


def format_csv(results: dict) -> str:
    output = io.StringIO()
    all_findings = (
        results.get("secrets", []) +
        results.get("security_issues", []) +
        results.get("vuln_libs", [])
    )
    if not all_findings:
        return ""
    fields = ["type", "pattern", "severity", "group", "confidence_score",
              "confidence_label", "value", "source_url", "line", "description"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for f in all_findings:
        row      = {k: f.get(k, "") for k in fields}
        row["type"] = f.get("type", "secret")
        val         = str(row.get("value", ""))
        row["value"]= val[:8] + "..." + val[-4:] if len(val) > 16 else val
        writer.writerow(row)
    return output.getvalue()


def format_sarif(results: dict, tool_version: str = "3.0.0") -> dict:
    rules: dict[str, dict] = {}
    run_results: list[dict] = []
    all_findings = (
        results.get("secrets", []) +
        results.get("security_issues", []) +
        results.get("vuln_libs", [])
    )
    for f in all_findings:
        rule_id = re.sub(r"[^a-zA-Z0-9_\-]", "-", f.get("pattern", "unknown"))
        sev     = f.get("severity", "low")
        level   = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(sev, "note")
        rank    = {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(sev, 10)
        if rule_id not in rules:
            rules[rule_id] = {
                "id":               rule_id,
                "name":             f.get("pattern", "Unknown"),
                "shortDescription": {"text": f.get("description", f.get("pattern", ""))},
                "fullDescription":  {"text": f.get("description", f.get("pattern", ""))},
                "defaultConfiguration": {"level": level, "rank": rank},
                "properties": {
                    "tags":     [f.get("group", ""), "security", "jsreaper"],
                    "severity": sev,
                    "group":    f.get("group", ""),
                    "cves":     f.get("cves", []),
                },
            }
        val  = f.get("value", "")
        mask = val[:8] + "***" + val[-4:] if len(val) > 16 else val
        run_results.append({
            "ruleId": rule_id,
            "level":  level,
            "message": {"text": f"{f.get('pattern', '')}  {mask}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("source_url", ""), "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": max(1, int(f.get("line", 1) or 1)),
                        "snippet":   {"text": (f.get("context") or f.get("value", ""))[:512]},
                    },
                }
            }],
            "properties": {
                "severity":         sev,
                "confidence_score": f.get("confidence_score", 0),
                "confidence_label": f.get("confidence_label", ""),
                "group":            f.get("group", ""),
                "value_masked":     mask,
                "cves":             f.get("cves", []),
            },
        })
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":            "JSReaper",
                    "informationUri":  "https://github.com/krumoist/jsreaper",
                    "version":         tool_version,
                    "semanticVersion": tool_version,
                    "rules":           list(rules.values()),
                    "properties":      {"tags": ["security", "secret-detection", "sast", "red-team"]},
                }
            },
            "results":    run_results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc":        results.get("scan_start", ""),
                "endTimeUtc":          results.get("scan_end", ""),
            }],
            "properties": {"target": results.get("target", "")},
        }]
    }
