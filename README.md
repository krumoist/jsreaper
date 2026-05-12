<div align="center">

```
     ██╗███████╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
     ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
     ██║███████╗██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██   ██║╚════██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
╚█████╔╝███████║██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
 ╚════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

**Elite JavaScript Secret Hunter and Security Scanner**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Patterns](https://img.shields.io/badge/Patterns-200%2B-red?style=flat-square)
![Security Checks](https://img.shields.io/badge/Security%20Checks-44-orange?style=flat-square)
![CVE Database](https://img.shields.io/badge/CVE%20Database-30%2B-critical?style=flat-square)

*Built for red teamers, penetration testers, and bug bounty hunters*

</div>

---

## Overview

JSReaper is a professional JavaScript reconnaissance and secret hunting tool engineered for offensive security engagements. Point it at any web target and it will crawl every JS file, parse React and Next.js application data structures, bypass WAF controls, and surface exposed secrets, insecure code patterns, vulnerable libraries, and hidden endpoints across your entire attack surface.

It understands modern web architecture at a deep level. It knows how webpack chunks lazy load, how Next.js embeds server state in `__NEXT_DATA__`, how Turbopack emits RSC payloads, and how Vite manifests work. None of that is invisible to JSReaper.

---

## Capabilities at a Glance

```
╔══════════════════════════════════════════════════════════════════════════╗
║  Secret Detection       200+ patterns across every major SaaS platform  ║
║  Security Analysis      44 static checks across 12 vulnerability classes ║
║  CVE Database           30+ CVEs across 20 JavaScript libraries          ║
║  WAF Evasion            60+ browser UAs, Cloudflare bypass, IP spoofing  ║
║  OSINT Integration      7 parallel intelligence sources                  ║
║  Output Formats         Text  JSON  CSV  SARIF 2.1.0                     ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## Install

```bash
git clone https://github.com/krumoist/jsreaper
cd jsreaper
pip install requests
python jsreaper.py https://target.com
```

No additional dependencies. No virtual environment needed. Just Python and requests.

---

## Quick Start

```bash
python jsreaper.py https://app.target.com

python jsreaper.py https://target.com --waf-bypass --rotate-ua --spoof-ip

python jsreaper.py https://target.com --intel --probe --nested-scan

python jsreaper.py https://target.com --severity critical --output-format sarif --output scan.sarif

python jsreaper.py https://target.com --waf-bypass --cf-bypass --proxy http://127.0.0.1:8080 --no-ssl-verify
```

---

## Secret Detection

Over 200 patterns covering every major SaaS, cloud, and infrastructure provider. Each pattern has a severity level and format validator that confirms the value actually matches the expected format before scoring it as a finding.

**Cloud Providers**

```
AWS           AKIA keys, ABIA, ACCA, ASIA, secret access keys, session tokens
              S3 bucket URLs, ARNs, Cognito identity pools and user pool IDs
Google        API keys, OAuth2 client secrets, service account JSON blobs
              Firebase configs, database URLs, GCP project IDs
Azure         Storage connection strings, Active Directory client secrets
Cloudflare    API keys, API tokens
```

**Code and Dev Platforms**

```
GitHub        Personal access tokens (classic and fine-grained), OAuth tokens
              App tokens (ghs, ghu, ghr), installation tokens
NPM           npm_ tokens
PyPI          pypi- tokens
Vercel        Deployment tokens
Doppler       dp.pt. service tokens
HashiCorp     Vault tokens
Terraform     Cloud tokens (atlasv1)
CircleCI      API tokens
Pulumi        Access tokens (pul-)
```

**AI and Machine Learning**

```
OpenAI        sk-proj- and legacy sk- keys
Anthropic     sk-ant-api03- keys
HuggingFace   hf_ tokens
Groq          gsk_ keys
Cohere        API keys
Replicate     r8_ tokens
Mistral       API keys
Together AI   64-char API keys
Perplexity    pplx- keys
ElevenLabs    API keys
Stability AI  API keys
Weaviate      API keys
Pinecone      API keys
```

**Payments and Finance**

```
Stripe        Live and test secret keys, webhook secrets, restricted keys
              Publishable keys (all variants)
Shopify       Admin tokens (shpat), private app tokens (shppa), storefront (shpss)
Square        Access tokens (sq0)
PayPal        Production access tokens
Plaid         Client ID and client secret
Wise          API tokens
Braintree     Private and public keys
LemonSqueezy  API keys
Tebex         Secret keys
```

**Authentication and Identity**

```
Auth0         Client secrets, management tokens
Okta          API tokens (00...)
Clerk         Secret keys (sk_live_, sk_test_), publishable keys
WorkOS        API keys
Stytch        Project secrets (secret-live-), project IDs
Firebase      API keys, config objects
reCAPTCHA     Site keys and secret keys
NextAuth      NEXTAUTH_SECRET values
JWT           Signed tokens (with payload decode)
```

**Communication and Messaging**

```
Slack         Bot tokens (xoxb), user tokens (xoxp), app tokens (xapp)
              Webhook URLs, signing secrets
Discord       Bot tokens, webhook URLs, verify keys, client secrets
Twilio        Account SIDs, auth tokens
Telegram      Bot tokens
Pusher        App secrets and keys
Ably          API keys
SendBird      Master API keys
WhatsApp      Business access tokens
```

**Email Platforms**

```
SendGrid      SG. keys
Mailgun       key- tokens
Postmark      Server tokens
Resend        re_ keys
Brevo         xkeysib- keys
Mailchimp     API keys with datacenter suffix
Mailjet       API and secret keys
SparkPost     API keys
Klaviyo       API keys and public keys
SMTP          Passwords from config objects
```

**Databases**

```
MongoDB       Connection strings with credentials
PostgreSQL    Connection strings (postgres://, postgresql://)
MySQL         Connection strings
Redis         redis:// and rediss:// with authentication
Supabase      Anon keys and service role keys, project URLs
PlanetScale   psdb.cloud connection strings
Neon          neon.tech connection strings
Turso         libsql:// URLs
Upstash       upstash.io Redis URLs
Snowflake     Account credentials
Databricks    dapi tokens
```

**Analytics, Monitoring, and CRM**

```
Analytics     Segment write keys, Amplitude API keys, Mixpanel tokens
              PostHog (phc_) keys, Hotjar site IDs, FullStory org IDs
Monitoring    Sentry DSNs, Datadog API and app keys, New Relic license keys
              Rollbar tokens, Bugsnag API keys, LogRocket app IDs
              Sumo Logic access keys
CRM           HubSpot API keys and PAT tokens, Salesforce access tokens
              Intercom tokens, Zendesk API tokens, Freshdesk API keys
```

**Feature Flags, CMS, Search**

```
Feature Flags LaunchDarkly SDK keys (sdk-) and client keys
              Split.io SDK keys, Unleash API tokens
CMS           Contentful delivery and management tokens (CFPAT-)
              Sanity project IDs and tokens, Webflow API tokens
Search        Algolia app IDs, admin keys, and search keys
```

**Productivity and Automation**

```
Productivity  Linear (lin_api_), Notion (secret_), Airtable (pat...)
              ClickUp (pk_), Asana, Monday.com, Jira, Figma, Retool, Zoom
Automation    Zapier webhook URLs, Make.com webhook URLs, Workato webhooks
Web3          Alchemy API keys, Infura project secrets, Moralis API keys
              WalletConnect project IDs
Cryptography  RSA, EC, OpenSSH, PGP private keys, hex encryption keys
Logistics     Shippo (shippo_live_), EasyPost (EZ...)
HR            Rippling tokens, Lever API keys
Framework     Django SECRET_KEY, Rails secret_key_base, Laravel APP_KEY
              Vite VITE_ prefixed variables, Base64 Laravel keys
```

---

## Security Analysis

44 static analysis checks across 12 vulnerability classes. Each finding includes the vulnerable code snippet, source file, line number, and a human-readable description.

```
╔════════════════════════╦═══════╦══════════════════════════════════════════╗
║ Check                  ║ Sev   ║ What It Catches                          ║
╠════════════════════════╬═══════╬══════════════════════════════════════════╣
║ eval() sink            ║ HIGH  ║ eval() with dynamic non-literal argument ║
║ innerHTML assignment   ║ HIGH  ║ innerHTML set from variable              ║
║ outerHTML assignment   ║ HIGH  ║ outerHTML set from variable              ║
║ document.write         ║ HIGH  ║ document.write/writeln                   ║
║ setTimeout string      ║ MED   ║ setTimeout with string argument (eval)   ║
║ setInterval string     ║ MED   ║ setInterval with string argument (eval)  ║
║ dangerouslySetInnerHTML║ HIGH  ║ React XSS injection point                ║
║ insertAdjacentHTML     ║ HIGH  ║ DOM insertion with dynamic content       ║
║ Function() constructor ║ HIGH  ║ new Function() = eval equivalent         ║
║ jQuery .html() sink    ║ MED   ║ .html() called with dynamic data         ║
║ jQuery DOM manip       ║ MED   ║ .append/.prepend with untrusted input    ║
║ srcdoc dynamic         ║ HIGH  ║ srcdoc iframe attribute set dynamically  ║
║ document.domain write  ║ MED   ║ Same-origin policy weakened              ║
╠════════════════════════╬═══════╬══════════════════════════════════════════╣
║ __proto__ assignment   ║ CRIT  ║ Direct prototype pollution               ║
║ constructor.prototype  ║ HIGH  ║ Prototype chain manipulation             ║
║ Recursive merge        ║ MED   ║ deepMerge/extend with prototype risk     ║
║ Object.assign + req    ║ LOW   ║ Merge with request-controlled source     ║
╠════════════════════════╬═══════╬══════════════════════════════════════════╣
║ Cloud metadata fetch   ║ CRIT  ║ 169.254.169.254 / metadata.google.int   ║
║ SSRF via URL param     ║ HIGH  ║ fetch() URL from request parameter       ║
║ Hardcoded loopback     ║ MED   ║ fetch() to localhost/127.0.0.1           ║
╠════════════════════════╬═══════╬══════════════════════════════════════════╣
║ CORS wildcard          ║ MED   ║ Access-Control-Allow-Origin: *           ║
║ CORS reflect origin    ║ HIGH  ║ Origin header reflected back             ║
║ CORS creds + wildcard  ║ CRIT  ║ Credentials: true with wildcard origin   ║
╠════════════════════════╬═══════╬══════════════════════════════════════════╣
║ exec() with user input ║ CRIT  ║ OS command injection                     ║
║ require() + user input ║ CRIT  ║ Arbitrary module loading                 ║
║ node-serialize RCE     ║ CRIT  ║ serialize.unserialize() call             ║
║ Template engine SSTI   ║ CRIT  ║ ejs/pug/handlebars/nunjucks + user data  ║
╠════════════════════════╬═══════╬══════════════════════════════════════════╣
║ SQL concatenation      ║ CRIT  ║ SELECT/INSERT built with string concat   ║
║ SQL template literal   ║ HIGH  ║ SQL query using ${userInput}             ║
╠════════════════════════╬═══════╬══════════════════════════════════════════╣
║ fs.readFile user path  ║ HIGH  ║ File read with request-controlled path   ║
║ path.join user input   ║ HIGH  ║ Path traversal via path.join             ║
╠════════════════════════╬═══════╬══════════════════════════════════════════╣
║ JWT none algorithm     ║ CRIT  ║ Algorithm set to "none"                  ║
║ JWT unverified decode  ║ CRIT  ║ jwt.decode without verification          ║
║ JWT weak secret        ║ HIGH  ║ jwt.sign with hardcoded weak string      ║
╠════════════════════════╬═══════╬══════════════════════════════════════════╣
║ JWT in localStorage    ║ HIGH  ║ Token stored where XSS can steal it      ║
║ Sensitive key storage  ║ MED   ║ Auth/session data in localStorage        ║
╠════════════════════════╬═══════╬══════════════════════════════════════════╣
║ Open redirect href     ║ MED   ║ location.href from request source        ║
║ Open redirect res      ║ MED   ║ res.redirect() with user URL             ║
║ PostMessage no origin  ║ MED   ║ message listener without origin check    ║
║ PostMessage wildcard   ║ MED   ║ postMessage to * target                  ║
║ ReDoS via RegExp       ║ MED   ║ new RegExp(userInput)                    ║
║ XXE via XML parser     ║ MED   ║ libxmljs/xml2js/DOMParser + user data    ║
╚════════════════════════╩═══════╩══════════════════════════════════════════╝
```

---

## Vulnerable Library Detection

Version-aware CVE matching across 20 JavaScript libraries. Detects the library version from the URL or filename, compares it against the CVE database, and reports the exact fix version needed.

```
Library         Vulnerabilities
jQuery          CVE-2020-11022  CVE-2020-11023  XSS via .html()/.append()
                CVE-2019-11358  Prototype pollution via $.extend(true, ...)
                CVE-2012-6708   XSS via location.hash
lodash          CVE-2021-23337  Command injection via _.template
                CVE-2020-8203   Prototype pollution via _.merge
                CVE-2019-10744  Prototype pollution via _.defaultsDeep
moment.js       CVE-2022-24785  CVE-2022-31129  ReDoS via date parser
axios           CVE-2020-28168  SSRF via cross-domain redirect
                CVE-2023-45857  CSRF via arbitrary request headers
handlebars      CVE-2021-23369  CVE-2021-23383  Prototype pollution and RCE
                CVE-2019-19919  Prototype pollution via nested helpers
Bootstrap       CVE-2018-14040  CVE-2018-14042  XSS in tooltip/popover
                CVE-2019-8331   XSS via data-content and data-title
AngularJS       CVE-2020-7676   XSS via JQLite bypass
                CVE-2016-9879   Sandbox escape for arbitrary JS execution
DOMPurify       CVE-2022-37601  mXSS bypass
                CVE-2024-45801  XSS bypass via namespace confusion
elliptic        CVE-2020-28498  Timing side-channel on scalar multiplication
json5           CVE-2022-46175  Prototype pollution via JSON.parse
socket.io       CVE-2022-2421   Unauthorized access misconfiguration
underscore      CVE-2021-23358  Arbitrary code execution via template
highlight.js    CVE-2020-26237  ReDoS via language grammars
marked          CVE-2022-21681  CVE-2022-21680  ReDoS via markdown
Vue.js          CVE-2024-6257   XSS via v-html with unescaped input
Next.js         CVE-2024-34351  SSRF via Host header in Server Actions
                CVE-2023-46298  DoS via crafted app directory request
Express         CVE-2024-29041  Open redirect via malformed URL
minimatch       CVE-2022-3517   ReDoS via crafted glob pattern
semver          CVE-2022-25883  ReDoS via crafted semver string
tough-cookie    CVE-2023-26136  Prototype pollution via cookie domain
```

---

## WAF Bypass

Full browser impersonation with matching header sets. Not just a User-Agent swap.

```
Chrome 121-124    Complete Sec-Ch-Ua header family with full version lists
                  Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Sec-Fetch-User
                  Sec-Ch-Ua-Mobile, Sec-Ch-Ua-Platform, Upgrade-Insecure-Requests
                  Optional Sec-Ch-Ua-Arch and Sec-Ch-Ua-Bitness headers

Firefox 115/123/124   TE: trailers, correct Accept header, Sec-Fetch headers
Safari 17.x           Platform-native headers without Sec-Ch-Ua
Edge 124              Chromium-based with Edge-specific Sec-Ch-Ua string
Mobile UAs            Android 14, Pixel 8, Samsung S908, iPhone iOS 17.4, iPad

Bot Impersonation     Googlebot, Bingbot, GPTBot, facebookexternalhit, Twitterbot
                      LinkedInBot, Slackbot, AhrefsBot, SemrushBot, DotBot

IP Spoofing Headers   X-Forwarded-For, CF-Connecting-IP, True-Client-IP
                      X-Real-IP, X-Originating-IP, X-Remote-IP, X-Client-IP
                      Forwarded, X-Cluster-Client-IP, Via (with chain support)

Cloudflare Bypass     CF-IPCountry with random legitimate country code

Rate Limit Handling   Exponential backoff with jitter on 429 and 403
                      Retry-After header honoured
                      Automatic UA rotation on every retry attempt
                      Up to 6 retry attempts before marking URL as blocked

Connection Settings   pool_connections=50, pool_maxsize=50 for sustained crawls
```

---

## React and Next.js Support

The most common reason secret scanners miss findings on modern web apps is that they only scan downloaded .js files and ignore the data embedded directly in the HTML. JSReaper fixes that.

```
Inline scripts      All <script> blocks scanned before any .js files are fetched
__NEXT_DATA__       Server state JSON parsed and recursively secret-scanned
Build manifests     _buildManifest.js and _ssgManifest.js auto-discovered
                    _next/app-build-manifest.json for App Router apps
Chunk discovery     _next/static/chunks/** URLs extracted and scanned
Turbopack           __turbopack_load__() calls discovered and followed
RSC payloads        self.__next_f.push() fragments extracted and scanned
importmap           <script type="importmap"> parsed for all module URLs
modulepreload       <link rel="modulepreload"> hrefs collected
Data layers         dataLayer, __REDUX_STATE__, __APP_STATE__, __INITIAL_STATE__
Vite manifests      manifest.json, .vite/manifest.json, build/manifest.json
JS in JS            Secondary pass over JS content to discover lazy-loaded chunks
```

---

## OSINT Intelligence Gathering

Run `--intel` to pull historical JS URLs and subdomain data from 7 sources in parallel before the main scan starts. All discovered URLs get fed into the crawler automatically.

```
URLScan.io        Scan history for the target domain including all linked JS files
CommonCrawl       CDX API index of all archived JS URLs from the crawl corpus
Wayback Machine   CDX API for JS files captured in Internet Archive
crt.sh            SSL certificate transparency logs for subdomain enumeration
HackerTarget      Host search API for additional subdomain data
AlienVault OTX    URL lists and passive DNS subdomain data
GitHub Search     Code search for files referencing the target domain

Live Probing      After subdomain enumeration, probe each host for live status
                  Discover JS files from all live subdomains
                  Merge everything into a single unified URL set before scanning
```

---

## Deep Extraction

Beyond secrets, JSReaper extracts structured intelligence from every file it processes.

```
Emails            All email addresses with false-positive filtering
Subdomains        Hostname discovery via URL pattern matching
AWS Account IDs   Extracted from accountId references in JS config
Cloud Buckets     S3, Google Cloud Storage, Azure Blob, Cloudflare R2
                  DigitalOcean Spaces, Backblaze B2
URL Parameters    GET parameter names from all discovered URLs
JWT Payloads      JWT tokens decoded and claims printed
GitHub Repos      github.com/org/repo references found in source
Docker Images     docker.io image references
API Versions      /v1/, /v2/, /alpha/, /beta/ path patterns
Interesting Code  TODO, FIXME, HACK, SECURITY, WARN comments
                  Inline base64 data URIs decoded and exposed
```

---

## Endpoint Discovery

18 categories of endpoint extraction with active probing support.

```
API paths         /api/**, /v1/**, /rest/**, /graphql, /rpc, /internal
GraphQL           GraphQL endpoint URLs with schema introspection hints
WebSockets        ws:// and wss:// connection URLs
Admin paths       /admin/**, /dashboard/**, /console/**, /backoffice/**
Dev paths         /debug/**, /health/**, /metrics/**, /pprof/**
OAuth             Authorization, token, and callback endpoint URLs
CDN assets        cdn., assets., static., media. subdomain URLs
S3 endpoints      amazonaws.com presigned and public URL patterns
Supabase          REST, auth, storage, and functions endpoint URLs
Fetch calls       fetch() and axios() call destinations extracted from code
Redirect URIs     OAuth redirect_uri parameter values
Form actions      HTML form action attributes
Storage keys      localStorage.setItem key names (reveals data architecture)
```

Active probing with `--probe` fires HEAD requests at every discovered endpoint and reports the HTTP status, Server header, X-Powered-By, and CORS configuration.

---

## Confidence Scoring

Every finding gets a score from 0 to 100. Format validators fire on 20+ pattern types. A confirmed GitHub PAT gets +15 if it matches `^ghp_[0-9A-Za-z]{36}$` and -20 if it does not.

```
Score Range     Label        Meaning
88 to 100       CONFIRMED    Format validated, high entropy, no false positive hints
65 to 87        LIKELY       Strong signal, minor uncertainty
40 to 64        POSSIBLE     Moderate signal, review recommended
0 to 39         UNLIKELY     Probably a false positive
```

Shannon entropy analysis catches secrets missed by pattern matching. Character uniqueness ratio removes repetitive low-entropy strings that regex sometimes matches incorrectly.

---

## Output Formats

```bash
python jsreaper.py https://target.com --output-format text
python jsreaper.py https://target.com --output-format json    --output results.json
python jsreaper.py https://target.com --output-format csv     --output results.csv
python jsreaper.py https://target.com --output-format sarif   --output results.sarif
```

SARIF 2.1.0 output integrates directly with GitHub Advanced Security, GitLab SAST, and any SAST pipeline that accepts the standard format.

---

## Full CLI Reference

```
positional:
  url                     Target URL to scan

Crawling:
  --depth N               Page crawl depth (default 2)
  --threads N             Parallel fetch threads (default 10)
  --timeout N             Request timeout in seconds (default 15)
  --delay N               Delay between requests in seconds
  --jitter N              Random jitter added to delay
  --max-js N              Maximum JS files to scan (default 500)
  --scope DOMAIN ...      Restrict crawl to these domains
  --extra-urls URL ...    Additional JS URLs to include in scan
  --nested-scan           Recursively scan base64 and JSON blobs for secrets

WAF Bypass:
  --waf-bypass            Enable full WAF bypass mode
  --rotate-ua             Rotate User-Agent on every request
  --spoof-ip              Add IP spoofing headers to every request
  --cf-bypass             Add Cloudflare-specific bypass headers
  --user-agent UA         Use a fixed User-Agent string
  --proxy URL             Route all traffic through a proxy
  --no-ssl-verify         Disable SSL certificate verification
  --headers H [H ...]     Add extra request headers (Name: Value)
  --cookies STR           Cookie string to include in all requests
  --backoff-delay N       Base backoff delay on rate limit (default 2.0s)
  --max-retries N         Maximum retry attempts on rate limit (default 6)

Scanning:
  --intel                 Enable parallel OSINT intelligence gathering
  --probe                 Actively HEAD-probe all discovered endpoints
  --nested-scan           Base64 and JSON blob recursive secret scan
  --deobfuscate           Deobfuscate JS before scanning
  --entropy               Enable entropy-based secret detection
  --entropy-threshold N   Minimum Shannon entropy threshold (default 4.0)
  --min-secret-len N      Minimum secret value length (default 16)
  --severity LEVEL        Minimum severity: critical high medium low
  --min-confidence N      Minimum confidence score 0 to 100
  --secrets-only          Only output secrets, skip all other checks
  --endpoints-only        Only output endpoints
  --no-security           Skip security checks
  --no-vuln-libs          Skip vulnerable library detection
  --no-intel              Skip OSINT output section
  --no-extraction         Skip deep extraction
  --patterns FILE         Load additional patterns from JSON file
  --disable-pattern NAME  Disable a specific pattern by exact name
  --no-unique             Do not deduplicate findings across files

Output:
  --output-format FORMAT  text json csv sarif
  --output FILE           Write output to file
  --show-context          Show surrounding code context with each finding
  --context-lines N       Lines of context to display (default 3)
  --no-color              Disable all ANSI colors
  --no-banner             Suppress the startup banner
  --quiet  -q             Suppress all stderr output
  --verbose  -v           Enable debug logging
```

---

## Custom Pattern Format

Drop a JSON file with your own patterns and pass it via `--patterns`:

```json
[
  {
    "name": "Internal Service Token",
    "severity": "critical",
    "group": "Custom",
    "regex": "ist_[a-zA-Z0-9]{40}"
  },
  {
    "name": "Company API Key",
    "severity": "high",
    "group": "Custom",
    "regex": "companyname_[a-f0-9]{32}"
  }
]
```

---

## Exit Codes

```
0     Clean scan, no critical severity secrets found
1     Fatal error during scan
2     Critical severity secrets found (useful for CI/CD pipeline gates)
```

---

## File Structure

```
jsreaper/
  jsreaper.py               Entry point and CLI argument parser
  core/
    patterns.py             200+ compiled regex patterns with severity and group
    scanner.py              Core scan engine with nested secret detection
    crawler.py              Web crawler with React/Next.js/Vite support
    engine.py               Orchestrator tying all modules together
    confidence.py           Scoring engine with format validators
    waf_bypass.py           WAF evasion session builder
    security_checks.py      44 static security analysis rules
    vuln_libs.py            Vulnerable library CVE database
    intel.py                OSINT intelligence gathering
    extractor.py            Deep data extraction
    endpoints.py            Endpoint pattern extraction
    deobfuscate.py          JS deobfuscation routines
    entropy.py              Shannon entropy analysis
  output/
    formatter.py            Terminal, JSON, CSV, and SARIF output
  requirements.txt          Runtime dependencies
```

---

## Legal

This tool is provided for authorized penetration testing, red team engagements, bug bounty programs, and security research on systems you own or have explicit written permission to test. Unauthorized use against systems without permission is illegal. The author assumes no liability for misuse.

---

<div align="center">

Built with precision for the offensive security community

</div>
