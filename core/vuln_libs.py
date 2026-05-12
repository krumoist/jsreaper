from __future__ import annotations
import re

_LIBRARIES: list[dict] = [
    {"name": "jQuery",           "regex": r"""jquery[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 9.8,
     "vulns": [
        {"fix": "3.5.0", "cves": ["CVE-2020-11022", "CVE-2020-11023"], "severity": "high",
         "desc": "XSS via .html()/.append() — affected 3.4.x and below"},
        {"fix": "3.4.0", "cves": ["CVE-2019-11358"],                   "severity": "medium",
         "desc": "Prototype pollution via $.extend(true, ...)"},
        {"fix": "1.9.0", "cves": ["CVE-2012-6708"],                    "severity": "medium",
         "desc": "XSS via location.hash"},
    ]},
    {"name": "lodash",           "regex": r"""lodash[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 9.1,
     "vulns": [
        {"fix": "4.17.21", "cves": ["CVE-2021-23337"],                          "severity": "critical",
         "desc": "Command injection via _.template"},
        {"fix": "4.17.21", "cves": ["CVE-2020-8203"],                           "severity": "high",
         "desc": "Prototype pollution via _.merge, _.mergeWith, _.defaultsDeep"},
        {"fix": "4.17.15", "cves": ["CVE-2019-10744"],                          "severity": "critical",
         "desc": "Prototype pollution via _.defaultsDeep"},
    ]},
    {"name": "moment.js",        "regex": r"""moment[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 7.5,
     "vulns": [
        {"fix": "2.29.4", "cves": ["CVE-2022-24785", "CVE-2022-31129"], "severity": "high",
         "desc": "ReDoS via craft input to date parser"},
    ]},
    {"name": "axios",            "regex": r"""axios[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 7.5,
     "vulns": [
        {"fix": "0.21.1", "cves": ["CVE-2020-28168"], "severity": "medium",
         "desc": "SSRF via HTTP redirect via cross-domain request"},
        {"fix": "1.6.0",  "cves": ["CVE-2023-45857"], "severity": "medium",
         "desc": "CSRF via arbitrary request headers"},
    ]},
    {"name": "handlebars",       "regex": r"""handlebars[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 9.8,
     "vulns": [
        {"fix": "4.7.7", "cves": ["CVE-2021-23369", "CVE-2021-23383"], "severity": "critical",
         "desc": "Prototype pollution + RCE via template attribute"},
        {"fix": "4.5.3", "cves": ["CVE-2019-19919"],                   "severity": "critical",
         "desc": "Prototype pollution via nested helpers"},
    ]},
    {"name": "Bootstrap",        "regex": r"""bootstrap[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 6.1,
     "vulns": [
        {"fix": "3.4.0", "cves": ["CVE-2018-14040", "CVE-2018-14042"], "severity": "medium",
         "desc": "XSS via data-template in tooltip/popover"},
        {"fix": "4.3.1", "cves": ["CVE-2019-8331"],                   "severity": "medium",
         "desc": "XSS via data-content / data-title"},
    ]},
    {"name": "AngularJS",        "regex": r"""angular[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 9.8,
     "vulns": [
        {"fix": "1.8.0", "cves": ["CVE-2020-7676"], "severity": "high",
         "desc": "XSS via JQLite htmlInertContext bypass"},
        {"fix": "1.6.0", "cves": ["CVE-2016-9879"], "severity": "high",
         "desc": "Sandbox escape allowing arbitrary JS execution"},
    ]},
    {"name": "DOMPurify",        "regex": r"""dompurify[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 8.1,
     "vulns": [
        {"fix": "2.4.0", "cves": ["CVE-2022-37601"], "severity": "medium",
         "desc": "Bypass via mXSS using nesting quirks"},
        {"fix": "3.1.0", "cves": ["CVE-2024-45801"], "severity": "high",
         "desc": "XSS bypass via namespace confusion"},
    ]},
    {"name": "elliptic",         "regex": r"""elliptic[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 7.4,
     "vulns": [
        {"fix": "6.5.4", "cves": ["CVE-2020-28498"], "severity": "high",
         "desc": "Non-constant-time scalar multiplication — timing side-channel"},
    ]},
    {"name": "json5",            "regex": r"""json5[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 9.8,
     "vulns": [
        {"fix": "2.2.2", "cves": ["CVE-2022-46175"], "severity": "high",
         "desc": "Prototype pollution via JSON.parse replacement"},
    ]},
    {"name": "socket.io",        "regex": r"""socket\.io[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 7.5,
     "vulns": [
        {"fix": "4.5.2", "cves": ["CVE-2022-2421"], "severity": "high",
         "desc": "Unauthorized access due to misconfigured transport"},
    ]},
    {"name": "underscore",       "regex": r"""underscore[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 9.8,
     "vulns": [
        {"fix": "1.13.0-2", "cves": ["CVE-2021-23358"], "severity": "critical",
         "desc": "Arbitrary code execution via template function"},
    ]},
    {"name": "highlight.js",     "regex": r"""highlight(?:\.min)?[.\-_]v?(\d+\.\d+\.\d+)\.js""",
     "cvss_max": 7.5,
     "vulns": [
        {"fix": "10.4.1", "cves": ["CVE-2020-26237"], "severity": "medium",
         "desc": "ReDoS in several language grammars"},
    ]},
    {"name": "marked",           "regex": r"""marked[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 9.3,
     "vulns": [
        {"fix": "4.0.10", "cves": ["CVE-2022-21681", "CVE-2022-21680"], "severity": "high",
         "desc": "ReDoS via crafted markdown input"},
    ]},
    {"name": "Vue.js",           "regex": r"""vue[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 5.4,
     "vulns": [
        {"fix": "2.7.16", "cves": ["CVE-2024-6257"],  "severity": "medium",
         "desc": "XSS via v-html directive with unescaped input"},
    ]},
    {"name": "Next.js",          "regex": r"""next[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 9.1,
     "vulns": [
        {"fix": "14.1.1",  "cves": ["CVE-2024-34351"], "severity": "high",
         "desc": "SSRF via Host header manipulation in Server Actions"},
        {"fix": "13.5.1",  "cves": ["CVE-2023-46298"], "severity": "high",
         "desc": "DoS via crafted Next.js request to app directory"},
    ]},
    {"name": "Express",          "regex": r"""express[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 9.8,
     "vulns": [
        {"fix": "4.19.2",  "cves": ["CVE-2024-29041"], "severity": "medium",
         "desc": "Open redirect via malformed URL"},
    ]},
    {"name": "minimatch",        "regex": r"""minimatch[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 7.5,
     "vulns": [
        {"fix": "3.0.5", "cves": ["CVE-2022-3517"], "severity": "high",
         "desc": "ReDoS via crafted glob pattern"},
    ]},
    {"name": "semver",           "regex": r"""semver[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 7.5,
     "vulns": [
        {"fix": "7.5.2", "cves": ["CVE-2022-25883"], "severity": "medium",
         "desc": "ReDoS via crafted semver string"},
    ]},
    {"name": "tough-cookie",     "regex": r"""tough-cookie[.\-_]v?(\d+\.\d+\.\d+)(?:\.min)?\.js""",
     "cvss_max": 9.8,
     "vulns": [
        {"fix": "4.1.3", "cves": ["CVE-2023-26136"], "severity": "critical",
         "desc": "Prototype pollution via cookie domain"},
    ]},
]

_COMPILED = [
    {**lib, "compiled": re.compile(lib["regex"], re.I)}
    for lib in _LIBRARIES
]

_VERSION_RE = re.compile(r"""(\d+)\.(\d+)\.(\d+)""")


def _parse_version(v: str) -> tuple[int, int, int]:
    m = _VERSION_RE.search(v)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return (0, 0, 0)


def _version_lt(v: tuple, fix: str) -> bool:
    fix_t = _parse_version(fix)
    return v < fix_t


def scan_for_vulnerable_libs(content: str, source_url: str) -> list[dict]:
    findings = []
    for lib in _COMPILED:
        for m in lib["compiled"].finditer(content):
            raw_ver = m.group(1)
            ver_t   = _parse_version(raw_ver)
            if ver_t == (0, 0, 0):
                continue
            for vuln in lib["vulns"]:
                if _version_lt(ver_t, vuln["fix"]):
                    findings.append({
                        "pattern":          f"Vulnerable {lib['name']}",
                        "severity":         vuln["severity"],
                        "group":            "VulnLib",
                        "category":         "vulnerable_library",
                        "value":            f"{lib['name']} {raw_ver}",
                        "source_url":       source_url,
                        "line":             content[:m.start()].count("\n") + 1,
                        "context":          m.group(0),
                        "description":      vuln["desc"],
                        "cves":             vuln["cves"],
                        "fix_version":      vuln["fix"],
                        "cvss_max":         lib["cvss_max"],
                        "type":             "vulnerable_library",
                        "confidence_score": 90,
                        "confidence_label": "confirmed",
                    })
    return findings
