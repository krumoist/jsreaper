from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse

API_PATH_RE         = re.compile(r"""["'`]((?:/(?:api|v\d+|rest|gql|graphql|query|rpc|internal|admin|auth|oauth|webhook|ws|socket|stream|export|import|health|status|metrics|upload|download|cdn)[^\s"'`<>\],)]{0,120})["'`]""", re.I)
FULL_URL_RE         = re.compile(r"""["'`](https?://[^\s"'`<>\](){},]{8,300})["'`]""")
RELATIVE_PATH_RE    = re.compile(r"""["'`](/[a-zA-Z0-9_\-/]{2,120}(?:\?[^\s"'`<>\]]{0,80})?)["'`]""")
GRAPHQL_RE          = re.compile(r"""["'`]([^"'`\s]*/?graphql[^"'`\s]*)["'`]""", re.I)
WEBSOCKET_RE        = re.compile(r"""["'`](wss?://[^\s"'`<>\]]{8,200})["'`]""")
GRPC_RE             = re.compile(r"""\.(\w+)\s*=\s*new\s+\w+(?:Client|Stub)\s*\(""")
SWAGGER_RE          = re.compile(r"""["'`](/(?:swagger|openapi|api-docs|api/docs|redoc)[^"'`\s]*)["'`]""", re.I)
COOKIE_RE           = re.compile(r"""(?:document\.cookie|cookie)\s*(?:=|\+=)\s*["'`]?([a-zA-Z0-9_\-]+)\s*=""", re.I)
JWT_STORE_RE        = re.compile(r"""(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'`]([^"'`]{2,60})["'`]""")
REDIRECT_URI_RE     = re.compile(r"""redirect_uri\s*[:=]\s*["'`]([^"'`\s]{10,200})["'`]""", re.I)
S3_ENDPOINT_RE      = re.compile(r"""https://[a-zA-Z0-9\-._]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com[^"'`\s]*""")
FETCH_URL_RE        = re.compile(r"""(?:fetch|axios\.(?:get|post|put|patch|delete|request)|http\.(?:get|post|put|delete)|request)\s*\(["'`]([^"'`\s]{4,200})["'`]""", re.I)
NEXT_PAGE_RE        = re.compile(r"""["'`]((?:/[a-zA-Z0-9_\-]{1,40}){1,6}/?(?:\?[^"'`\s]{0,80})?)["'`]""")
ADMIN_PATH_RE       = re.compile(r"""["'`](/(?:admin|dashboard|manage|console|control|backoffice|superadmin|staff|ops)[^"'`\s]{0,80})["'`]""", re.I)
DEV_PATH_RE         = re.compile(r"""["'`](/(?:debug|dev|devtools|test|staging|qa|internal|health|ping|status|metrics|profiler|pprof)[^"'`\s]{0,80})["'`]""", re.I)
OAUTH_RE            = re.compile(r"""["'`](https?://[^"'`\s]+/(?:oauth|authorize|token|callback|auth)[^"'`\s]*)["'`]""", re.I)
CDN_ASSET_RE        = re.compile(r"""["'`](https?://(?:cdn\.|assets\.|static\.|media\.)[^"'`\s<>]{8,200})["'`]""")
NEXT_API_RE         = re.compile(r"""["'`](/api/[a-zA-Z0-9_\-/]{1,100}(?:\?[^"'`\s]{0,60})?)["'`]""")
FORM_ACTION_RE      = re.compile(r"""<form[^>]+action\s*=\s*["']([^"']{2,200})["']""", re.I)
SUPABASE_ENDPOINT   = re.compile(r"""https://[a-z0-9]{20}\.supabase\.(?:co|net|io)/(?:rest|auth|storage|functions)/v\d+[^\s"'`<>]*""")
SKIP_EXTENSIONS_RE  = re.compile(r"""\.(?:png|jpg|jpeg|gif|webp|svg|ico|mp4|mp3|woff|woff2|ttf|eot|css|pdf|zip|gz)(?:[?#]|$)""", re.I)
SKIP_VALUES_RE      = re.compile(r"""^(?:https?://(?:localhost|127\.0\.0\.1|example\.com|schema\.org|w3\.org|yourdomain\.com))|^//{0,1}$""", re.I)


def _valid(url: str, base: str = "") -> bool:
    if not url or len(url) < 4 or len(url) > 400:
        return False
    if SKIP_VALUES_RE.search(url):
        return False
    if SKIP_EXTENSIONS_RE.search(url):
        return False
    if any(x in url for x in ["../", "{", "{{", "__", "example", "placeholder", "your-"]):
        return False
    return True


def _full(path: str, base: str) -> str:
    if path.startswith("http"):
        return path
    if base:
        return urljoin(base, path)
    return path


def extract_endpoints(content: str, source_url: str, next_data: dict = None) -> dict:
    base    = source_url
    result  = {
        "api_paths":     set(),
        "full_urls":     set(),
        "graphql":       set(),
        "websockets":    set(),
        "admin_paths":   set(),
        "dev_paths":     set(),
        "oauth_urls":    set(),
        "cdn_assets":    set(),
        "s3_endpoints":  set(),
        "supabase":      set(),
        "fetch_calls":   set(),
        "redirect_uris": set(),
        "form_actions":  set(),
        "storage_keys":  set(),
    }

    for m in GRAPHQL_RE.finditer(content):
        v = m.group(1)
        if _valid(v, base):
            result["graphql"].add(_full(v, base))

    for m in WEBSOCKET_RE.finditer(content):
        v = m.group(1)
        if v and "example" not in v:
            result["websockets"].add(v)

    for m in SWAGGER_RE.finditer(content):
        v = m.group(1)
        if _valid(v, base):
            result["api_paths"].add(_full(v, base))

    for m in FULL_URL_RE.finditer(content):
        v = m.group(1)
        if _valid(v, base) and "." in urlparse(v).netloc:
            result["full_urls"].add(v)

    for m in API_PATH_RE.finditer(content):
        v = m.group(1)
        if _valid(v, base):
            result["api_paths"].add(_full(v, base))

    for m in NEXT_API_RE.finditer(content):
        v = m.group(1)
        if _valid(v, base):
            result["api_paths"].add(_full(v, base))

    for m in ADMIN_PATH_RE.finditer(content):
        v = m.group(1)
        if _valid(v, base):
            result["admin_paths"].add(_full(v, base))

    for m in DEV_PATH_RE.finditer(content):
        v = m.group(1)
        if _valid(v, base):
            result["dev_paths"].add(_full(v, base))

    for m in OAUTH_RE.finditer(content):
        v = m.group(1)
        if _valid(v):
            result["oauth_urls"].add(v)

    for m in CDN_ASSET_RE.finditer(content):
        v = m.group(1)
        if _valid(v):
            result["cdn_assets"].add(v)

    for m in S3_ENDPOINT_RE.finditer(content):
        result["s3_endpoints"].add(m.group(0))

    for m in SUPABASE_ENDPOINT.finditer(content):
        result["supabase"].add(m.group(0))

    for m in FETCH_URL_RE.finditer(content):
        v = m.group(1)
        if _valid(v, base):
            result["fetch_calls"].add(_full(v, base))

    for m in REDIRECT_URI_RE.finditer(content):
        v = m.group(1)
        if _valid(v):
            result["redirect_uris"].add(v)

    for m in FORM_ACTION_RE.finditer(content):
        v = m.group(1)
        if _valid(v, base):
            result["form_actions"].add(_full(v, base))

    for m in JWT_STORE_RE.finditer(content):
        result["storage_keys"].add(m.group(1))

    if next_data and isinstance(next_data, dict):
        for route in _extract_next_routes(next_data):
            result["api_paths"].add(route)

    return {k: sorted(v) for k, v in result.items() if v}


def _extract_next_routes(nd: dict) -> list[str]:
    routes = []
    for route, data in nd.get("props", {}).get("pageProps", {}).items():
        if isinstance(route, str) and route.startswith("/"):
            routes.append(route)
    for key in ["page", "pathname", "asPath", "route"]:
        v = nd.get(key) or nd.get("props", {}).get("pageProps", {}).get(key)
        if v and isinstance(v, str) and v.startswith("/"):
            routes.append(v)
    return routes
