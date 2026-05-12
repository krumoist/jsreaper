from __future__ import annotations
import re
import math
import base64

HIGH_CONFIDENCE = frozenset({
    "AWS Access Key ID", "GitHub PAT Classic", "GitHub Fine-Grained Token",
    "GitHub OAuth Token", "GitHub App Token", "Stripe Live Secret Key",
    "Stripe Webhook Secret", "Stripe Restricted Key", "Slack Bot Token",
    "Slack User Token", "Slack App Token", "Discord Webhook URL",
    "SendGrid API Key", "OpenAI API Key", "OpenAI API Key New",
    "Anthropic API Key", "HuggingFace API Token", "Groq API Key",
    "Replicate API Token", "NPM Token", "Shopify Admin Token",
    "Shopify Private App", "RSA Private Key", "EC Private Key",
    "OpenSSH Private Key", "PGP Private Key", "Laravel APP_KEY",
    "Mapbox Secret Token", "Resend API Key", "Brevo API Key",
    "Turso Database URL", "Upstash Redis URL", "Doppler Token",
    "ClickUp API Token", "Linear API Key", "Notion API Token",
    "Databricks Token", "Okta API Token", "HubSpot Access Token",
    "Salesforce Access Token", "PostHog API Key", "Contentful Management Token",
    "LaunchDarkly SDK Key", "Stytch Project Secret", "Pulumi Access Token",
    "Shippo API Key", "Mux Secret Key", "Perplexity API Key",
    "Twitch OAuth Token", "Clerk Secret Key",
})

LOW_CONFIDENCE = frozenset({
    "Hardcoded Password", "Hardcoded Secret or Key", "Bearer Token",
    "GCP Project ID", "reCAPTCHA Site Key", "Internal IP Address",
    "GraphQL Endpoint", "Vite VITE_ Secret", "Algolia App ID",
    "Hotjar Site ID", "FullStory Org ID", "Mixpanel Token",
    "Discord Application ID",
})

FALSE_POSITIVE_HINTS = frozenset({
    "example", "placeholder", "your_", "your-", "xxx", "test", "demo",
    "replace", "changeme", "insert", "here", "todo", "fixme", "sample",
    "fake", "dummy", "mock", "stub", "n/a", "none", "xxxxxxxx", "aaaaaaaaa",
    "00000000", "11111111", "12345678", "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG", "secret_key", "api_key", "my_token",
    "my_secret", "access_token", "auth_token", "jwt_secret",
})

ENV_RE = re.compile(r"process\.env\.|import\.meta\.env\.|os\.environ|getenv\(", re.I)
COMMENT_RE = re.compile(r"(?:^|\s)//.*$|/\*.*?\*/", re.MULTILINE | re.DOTALL)

FORMAT_VALIDATORS: dict[str, re.Pattern] = {
    "AWS Access Key ID":        re.compile(r"^(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}$"),
    "GitHub PAT Classic":       re.compile(r"^ghp_[0-9A-Za-z]{36}$"),
    "GitHub Fine-Grained Token": re.compile(r"^github_pat_[0-9A-Za-z_]{82}$"),
    "Stripe Live Secret Key":   re.compile(r"^sk_live_[0-9A-Za-z]{24,}$"),
    "Stripe Webhook Secret":    re.compile(r"^whsec_[0-9A-Za-z]{32,}$"),
    "Slack Bot Token":          re.compile(r"^xoxb-"),
    "SendGrid API Key":         re.compile(r"^SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}$"),
    "NPM Token":                re.compile(r"^npm_[A-Za-z0-9]{36}$"),
    "Doppler Token":            re.compile(r"^dp\.pt\."),
    "Replicate API Token":      re.compile(r"^r8_[A-Za-z0-9]{38}$"),
    "HuggingFace API Token":    re.compile(r"^hf_[A-Za-z0-9]{34}$"),
    "Groq API Key":             re.compile(r"^gsk_[A-Za-z0-9]{52}$"),
    "PostHog API Key":          re.compile(r"^phc_[A-Za-z0-9]{43}$"),
    "Perplexity API Key":       re.compile(r"^pplx-[A-Za-z0-9]{48}$"),
    "Shippo API Key":           re.compile(r"^shippo_(?:test|live)_[a-f0-9]{40}$"),
    "Pulumi Access Token":      re.compile(r"^pul-[a-f0-9]{40}$"),
    "Clerk Secret Key":         re.compile(r"^sk_(?:test|live)_[A-Za-z0-9]{40,}$"),
    "HubSpot Access Token":     re.compile(r"^pat-(?:na|eu|au)1-"),
    "Databricks Token":         re.compile(r"^dapi[0-9a-f]{32}$"),
    "Twitch OAuth Token":       re.compile(r"^oauth:[a-z0-9]{30}$"),
    "Stytch Project Secret":    re.compile(r"^secret-(?:test|live)-[A-Za-z0-9]{28}$"),
    "LaunchDarkly SDK Key":     re.compile(r"^sdk-[a-f0-9]{8}-[a-f0-9]{4}-"),
    "Linear API Key":           re.compile(r"^lin_api_[A-Za-z0-9]{40}$"),
    "Notion API Token":         re.compile(r"^secret_[A-Za-z0-9]{43}$"),
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def _unique_ratio(s: str) -> float:
    if not s:
        return 0.0
    return len(set(s)) / len(s)


def _looks_like_jwt(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    try:
        base64.b64decode(parts[0] + "==")
        base64.b64decode(parts[1] + "==")
        return True
    except Exception:
        return False


def score_finding(finding: dict) -> int:
    pattern  = finding.get("pattern", "")
    value    = finding.get("value", "")
    context  = finding.get("context") or ""
    src      = finding.get("source_url", "")

    if pattern in HIGH_CONFIDENCE:
        score = 95
    elif pattern in LOW_CONFIDENCE:
        score = 38
    else:
        score = 65

    if pattern in FORMAT_VALIDATORS:
        if FORMAT_VALIDATORS[pattern].search(value):
            score = min(100, score + 15)
        else:
            score -= 20

    val_lower = value.lower().strip("'\"` ")
    for hint in FALSE_POSITIVE_HINTS:
        if hint in val_lower:
            score -= 38
            break

    if pattern not in HIGH_CONFIDENCE:
        ent = _entropy(value)
        if ent > 5.0:     score += 15
        elif ent > 4.5:   score += 10
        elif ent > 3.8:   score += 5
        elif ent < 2.8:   score -= 28
        elif ent < 2.0:   score -= 42

        ur = _unique_ratio(value)
        if ur < 0.12:   score -= 32
        elif ur < 0.22: score -= 16

    if ENV_RE.search(context):
        score -= 22

    if COMMENT_RE.search(context[:200]):
        score -= 18

    ctx_lower = context.lower()
    if any(kw in ctx_lower for kw in ["authorization", "x-api-key", "bearer", "credentials"]):
        score += 12
    if any(kw in ctx_lower for kw in ["const ", "let ", "var ", "config", "= {"]):
        score += 7

    if any(x in src.lower() for x in ["__next_data__", "inline script", "rsc"]):
        score += 10

    if "wayback" in src.lower() or "web.archive.org" in src.lower():
        score -= 12

    if len(value) < 8:     score -= 35
    elif len(value) < 12:  score -= 12
    elif len(value) > 300: score -= 8

    if pattern == "JSON Web Token" and not _looks_like_jwt(value):
        score -= 30

    return max(0, min(100, score))


def confidence_label(score: int) -> str:
    if score >= 88: return "confirmed"
    if score >= 65: return "likely"
    if score >= 40: return "possible"
    return "unlikely"
