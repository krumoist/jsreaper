from __future__ import annotations
import re
import base64
from urllib.parse import parse_qs

EMAIL_RE         = re.compile(r"""[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}""")
EMAIL_SKIP_RE    = re.compile(r"""@(?:example|test|domain|email|your|sentry|w3|schema)\.|\.png@|\.jpg@""", re.I)
SUBDOMAIN_RE     = re.compile(r"""(?:https?://|["'`])([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?){2,}\.[a-zA-Z]{2,})(?:[/"'`?]|$)""")
AWS_ACCOUNT_RE   = re.compile(r"""(?:account.?id|AccountId|aws[_\-]?account)\s*[:=]\s*["']?([0-9]{12})["']?""", re.I)
S3_BUCKET_RE     = re.compile(r"""["'`]?([a-z0-9][a-z0-9.\-]{2,62}[a-z0-9])\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com["'`]?""", re.I)
GCS_BUCKET_RE    = re.compile(r"""(?:storage\.googleapis\.com/|gs://)([a-z0-9][a-z0-9_\-\.]{2,62}[a-z0-9])""", re.I)
AZURE_BLOB_RE    = re.compile(r"""([a-z0-9]{3,24})\.blob\.core\.windows\.net""", re.I)
R2_BUCKET_RE     = re.compile(r"""([a-z0-9][a-z0-9\-]{2,62})\.r2\.cloudflarestorage\.com""", re.I)
DO_SPACES_RE     = re.compile(r"""([a-z0-9][a-z0-9\-]{2,62})\.(?:nyc|ams|sgp|fra|sfo|tor)[0-9]?\.digitaloceanspaces\.com""", re.I)
B2_BUCKET_RE     = re.compile(r"""([a-z0-9][a-z0-9\-]{2,62})\.s3\.(?:[a-z0-9\-]+)\.backblazeb2\.com""", re.I)
URL_PARAM_RE     = re.compile(r"""["'`](?:https?://[^?"'`\s]+)?\?([^"'`\s#]{5,500})["'`]""")
COMMENT_RE       = re.compile(r"""(?://[^\n]*(?:password|secret|key|token|todo|fixme|hack|bypass|admin|root|cred|api|note|warning|danger)[^\n]*|/\*[^*]*(?:password|secret|key|token|todo|fixme|hack|bypass|admin|root|cred)[^*]*\*/)""", re.I)
API_VERSION_RE   = re.compile(r"""["'`](/v(?:[0-9]+|alpha|beta|rc[0-9]?)(?:/[^"'`\s]{0,60})?)["'`]""", re.I)
B64_DATA_RE      = re.compile(r"""data:(?:text|application)/(?:javascript|json|xml|x-sh|x-python|octet-stream);base64,([A-Za-z0-9+/=]{20,})""", re.I)
PHONE_RE         = re.compile(r"""(?:\+1[\s\-.]?)?\(?[2-9]\d{2}\)?[\s\-.]?[2-9]\d{2}[\s\-.]?\d{4}""")
GITHUB_ORG_RE    = re.compile(r"""github\.com/([a-zA-Z0-9\-]+)/([a-zA-Z0-9_\-\.]+)""")
DOCKER_IMAGE_RE  = re.compile(r"""docker\.io/([a-z0-9][a-z0-9_\-\.]+/[a-z0-9][a-z0-9_\-\.]+)(?::[a-zA-Z0-9_\-\.]+)?""")
SECRET_COMMENT_RE= re.compile(r"""//\s*(?:TODO|FIXME|HACK|XXX|NOTE|BUG|WORKAROUND|SECURITY|WARN)\s*:?\s*(.{10,300})""", re.I)
VERSION_LEAK_RE  = re.compile(r"""(?:version|v)\s*[:=]\s*["'](\d+\.\d+(?:\.\d+)?)["']""", re.I)
JWT_PAYLOAD_RE   = re.compile(r"""eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}""")

_SKIP_DOMAINS = frozenset({"example.com", "localhost", "schema.org", "w3.org",
                            "mozilla.org", "iana.org", "jquery.com", "google.com",
                            "microsoft.com", "apple.com", "cloudflare.com"})


def _decode_jwt_payload(token: str) -> str | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        padded = parts[1] + "=="
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        return decoded
    except Exception:
        return None


def extract_all(content: str, source_url: str, base_domain: str = "") -> dict:
    result: dict[str, set] = {
        "emails":               set(),
        "subdomains":           set(),
        "aws_account_ids":      set(),
        "cloud_buckets":        set(),
        "api_versions":         set(),
        "interesting_comments": set(),
        "url_params":           set(),
        "github_repos":         set(),
        "docker_images":        set(),
        "jwt_payloads":         set(),
        "version_numbers":      set(),
    }

    for m in EMAIL_RE.finditer(content):
        email = m.group(0)
        if not EMAIL_SKIP_RE.search(email) and len(email) < 100:
            result["emails"].add(email)

    for m in SUBDOMAIN_RE.finditer(content):
        host = m.group(1).lower()
        if not any(fp in host for fp in _SKIP_DOMAINS):
            if base_domain and base_domain in host:
                result["subdomains"].add(host)
            elif not base_domain and len(host) < 100:
                result["subdomains"].add(host)

    for m in AWS_ACCOUNT_RE.finditer(content):
        result["aws_account_ids"].add(m.group(1))

    for m in S3_BUCKET_RE.finditer(content):
        result["cloud_buckets"].add(f"s3://{m.group(1)}")
    for m in GCS_BUCKET_RE.finditer(content):
        result["cloud_buckets"].add(f"gs://{m.group(1)}")
    for m in AZURE_BLOB_RE.finditer(content):
        result["cloud_buckets"].add(f"azure://{m.group(1)}")
    for m in R2_BUCKET_RE.finditer(content):
        result["cloud_buckets"].add(f"r2://{m.group(1)}")
    for m in DO_SPACES_RE.finditer(content):
        result["cloud_buckets"].add(f"spaces://{m.group(1)}")
    for m in B2_BUCKET_RE.finditer(content):
        result["cloud_buckets"].add(f"b2://{m.group(1)}")

    for m in API_VERSION_RE.finditer(content):
        result["api_versions"].add(m.group(1))

    seen_params: set[str] = set()
    for m in URL_PARAM_RE.finditer(content):
        try:
            for k in parse_qs(m.group(1)):
                if k not in seen_params and len(k) < 80:
                    seen_params.add(k)
                    result["url_params"].add(k)
        except Exception:
            pass

    for m in COMMENT_RE.finditer(content):
        c = m.group(0).strip()[:300]
        if c:
            result["interesting_comments"].add(c)

    for m in SECRET_COMMENT_RE.finditer(content):
        result["interesting_comments"].add(m.group(1).strip()[:200])

    for m in B64_DATA_RE.finditer(content):
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            if len(decoded) > 10:
                result["interesting_comments"].add(f"[base64] {decoded[:200]}")
        except Exception:
            pass

    for m in GITHUB_ORG_RE.finditer(content):
        result["github_repos"].add(f"{m.group(1)}/{m.group(2)}")

    for m in DOCKER_IMAGE_RE.finditer(content):
        result["docker_images"].add(m.group(1))

    for m in JWT_PAYLOAD_RE.finditer(content):
        payload = _decode_jwt_payload(m.group(0))
        if payload and len(payload) > 5:
            result["jwt_payloads"].add(payload[:300])

    for m in VERSION_LEAK_RE.finditer(content):
        v = m.group(1)
        if not v.startswith("0.0"):
            result["version_numbers"].add(v)

    return {k: sorted(v) for k, v in result.items() if v}
