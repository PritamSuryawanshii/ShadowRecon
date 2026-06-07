"""shadowrecon/modules/_constants.py — Shared constants for all modules."""

# ── HTTP ──────────────────────────────────────────────────────────────────────
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
HEADERS_DEFAULT = {
    "User-Agent":      UA,
    "Accept-Language": "en-US,en;q=0.9",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ── Common ports ──────────────────────────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1433, 1521, 2222, 3000, 3306, 3389, 4443, 5432, 5900, 5985, 5986,
    6379, 7443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 27017, 50070, 2375, 2376, 4848, 7001, 7002,
]

PORT_NAMES = {
    21: "FTP",         22: "SSH",         23: "Telnet",      25: "SMTP",
    53: "DNS",         80: "HTTP",        110: "POP3",       143: "IMAP",
    443: "HTTPS",      445: "SMB",        465: "SMTPS",      587: "SMTP/TLS",
    993: "IMAPS",      995: "POP3S",      1433: "MSSQL",     1521: "Oracle DB",
    2222: "SSH-alt",   2375: "Docker",    2376: "Docker-TLS",3000: "Node/Dev",
    3306: "MySQL",     3389: "RDP",       4443: "HTTPS-alt", 4848: "GlassFish",
    5432: "PostgreSQL",5900: "VNC",       5985: "WinRM-HTTP",5986: "WinRM-HTTPS",
    6379: "Redis",     7001: "WebLogic",  7002: "WebLogic",  7443: "HTTPS-alt",
    8000: "Dev",       8008: "HTTP-alt",  8080: "HTTP-proxy",8081: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "Jupyter",   9000: "Portainer", 9090: "Prometheus",
    9200: "Elasticsearch", 9300: "ES-transport", 27017: "MongoDB",
    50070: "Hadoop HDFS",
}

RISKY_PORTS = {
    23:    ("Telnet", "CRITICAL", "Plaintext protocol — credential exposure (CWE-319)"),
    2375:  ("Docker API", "CRITICAL", "Unauthenticated Docker socket — RCE risk"),
    3389:  ("RDP", "HIGH", "Exposed RDP — bruteforce/BlueKeep/DejaBlue vectors"),
    5900:  ("VNC", "HIGH", "VNC often unauthenticated — remote desktop access"),
    5985:  ("WinRM HTTP", "HIGH", "Windows Remote Management — lateral movement"),
    6379:  ("Redis", "HIGH", "Redis often unauthenticated — RCE via config write"),
    9200:  ("Elasticsearch", "HIGH", "ES often unauthenticated — data exfiltration"),
    9300:  ("ES transport", "MEDIUM", "Elasticsearch internal transport exposed"),
    27017: ("MongoDB", "HIGH", "MongoDB often unauthenticated — data exfiltration"),
    1433:  ("MSSQL", "HIGH", "Direct DB exposure — credential/xp_cmdshell attack"),
    1521:  ("Oracle DB", "HIGH", "Direct Oracle DB exposure"),
    3306:  ("MySQL", "HIGH", "Direct MySQL exposure"),
    5432:  ("PostgreSQL", "HIGH", "Direct PostgreSQL exposure"),
    4848:  ("GlassFish", "MEDIUM", "GlassFish admin panel — default credentials"),
    7001:  ("WebLogic", "HIGH", "WebLogic — multiple critical CVEs (SSRF/RCE)"),
    7002:  ("WebLogic", "HIGH", "WebLogic — multiple critical CVEs"),
    50070: ("Hadoop", "HIGH", "Hadoop NameNode UI — often no auth"),
    8888:  ("Jupyter", "HIGH", "Jupyter Notebook — often no auth, RCE via kernel"),
}

# ── Subdomain takeover fingerprints ──────────────────────────────────────────
TAKEOVER_SIGS = {
    "github.io":              ("GitHub Pages",        "There isn't a GitHub Pages site here"),
    "amazonaws.com":          ("AWS S3",              "NoSuchBucket"),
    "s3.amazonaws.com":       ("AWS S3",              "NoSuchBucket"),
    "cloudfront.net":         ("CloudFront",          "Bad request"),
    "azurewebsites.net":      ("Azure Web Apps",      "404 Web Site not found"),
    "blob.core.windows.net":  ("Azure Blob",          "No webpage was found"),
    "fastly.net":             ("Fastly",              "Fastly error: unknown domain"),
    "herokussl.com":          ("Heroku",              "No such app"),
    "herokudns.com":          ("Heroku",              "No such app"),
    "herokuapp.com":          ("Heroku",              "No such app"),
    "shopify.com":            ("Shopify",             "Sorry, this shop is currently unavailable"),
    "desk.com":               ("Desk",                "Sorry, We Couldn't Find That Page"),
    "zendesk.com":            ("Zendesk",             "Help Center Closed"),
    "readme.io":              ("Readme.io",           "Project doesnt exist"),
    "surge.sh":               ("Surge.sh",            "project not found"),
    "unbounce.com":           ("Unbounce",            "The requested URL was not found"),
    "tumblr.com":             ("Tumblr",              "Whatever you were looking for doesn't live here"),
    "ghost.io":               ("Ghost",               "The thing you were looking for is no longer here"),
    "pantheon.io":            ("Pantheon",            "404 error unknown site"),
    "wpengine.com":           ("WP Engine",           "The site you were looking for couldn't be found"),
    "strikingly.com":         ("Strikingly",          "page not found"),
    "statuspage.io":          ("Statuspage",          "Better Uptime"),
    "bitbucket.io":           ("Bitbucket",           "Repository not found"),
    "webflow.io":             ("Webflow",             "The page you are looking for doesn't exist"),
    "helpscout.net":          ("Help Scout",          "No settings were found for this company"),
    "freshdesk.com":          ("Freshdesk",           "There is no helpdesk here"),
    "aftership.com":          ("AfterShip",           "Oops."),
    "mailchimp.com":          ("Mailchimp",           "Oops! That page doesn't exist"),
    "intercom.io":            ("Intercom",            "This page is reserved"),
    "fly.dev":                ("Fly.io",              "404 Not Found"),
    "vercel.app":             ("Vercel",              "The deployment could not be found"),
    "netlify.app":            ("Netlify",             "Not Found"),
    "netlify.com":            ("Netlify",             "Not Found"),
    "readthedocs.io":         ("ReadTheDocs",         "unknown to Read the Docs"),
    "launchrock.com":         ("LaunchRock",          "It looks like you may have taken a wrong turn"),
    "cargocollective.com":    ("Cargo Collective",    "404 Not Found"),
}

# ── WAF fingerprints ──────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":        ["cf-ray", "__cfduid", "cf-cache-status", "cloudflare"],
    "AWS WAF":           ["x-amzn-requestid", "x-amz-cf-id", "awselb", "x-amz-id"],
    "Akamai":            ["akamai", "ak_bmsc", "x-akamai-transformed", "x-check-cacheable"],
    "F5 BIG-IP ASM":     ["ts=", "x-wa-info", "bigipserver", "f5-ltm", "x-cnection"],
    "Imperva/Incapsula":  ["incap_ses", "visid_incap", "x-iinfo", "_incapsula_"],
    "Sucuri":            ["x-sucuri-id", "x-sucuri-cache", "sucuri"],
    "Barracuda":         ["bni__", "bni_persistence", "barracuda"],
    "ModSecurity":       ["mod_security", "modsec", "NOYB", "x-modsec"],
    "Fortinet":          ["fortigate", "fortibalancer", "cookiesession1"],
    "DDoS-Guard":        ["ddos-guard", "__ddg"],
    "Fastly":            ["fastly", "x-fastly-request-id", "x-served-by"],
    "Reblaze":           ["rbzid", "rbzsessionid"],
    "Wallarm":           ["x-wallarm-node"],
    "Nginx WAF":         ["x-denied-reason", "naxsi"],
    "Wordfence":         ["wordfence", "wfvt_"],
    "StackPath":         ["x-sp-url", "x-sp-request-id"],
    "Netlify":           ["x-nf-request-id"],
    "Cloudfront+Shield": ["x-amz-cf-pop", "x-amz-cf-id"],
}

WAF_BYPASS_HINTS = {
    "Cloudflare":        [
        "Use Unicode/UTF-8 obfuscation in payloads",
        "Try HTTP/2 request splitting",
        "Exploit case-folding in header names",
        "Test Content-Type confusion (JSON vs form-data)",
    ],
    "Akamai":            [
        "Try chunked Transfer-Encoding",
        "Use HTTP header injection (CR/LF)",
        "Test slow POST / large body padding",
        "Try X-Forwarded-For IP spoofing for geo-bypass",
    ],
    "AWS WAF":           [
        "JSON-encoded payloads bypass text-mode rules",
        "Double URL-encode special chars",
        "Exploit regex anchor issues with newlines",
        "Try Base64-encoded param values",
    ],
    "Imperva/Incapsula": [
        "Use multipart/form-data encoding",
        "HTTP Parameter Pollution (HPP) with array notation",
        "Charset confusion (UTF-7, UTF-16)",
        "Try comment injection in SQL payloads",
    ],
    "F5 BIG-IP ASM":     [
        "Alternate keyword casing in SQL/XSS",
        "Line continuation chars in JS expressions",
        "Try Unicode escapes in parameter values",
    ],
    "ModSecurity":       [
        "SQL comment injection: UN/**/ION SE/**/LECT",
        "Use null bytes between keywords",
        "HPP to split attack across multiple params",
        "Try HTTP verb tunnelling (X-HTTP-Method-Override)",
    ],
}

# ── Security headers ──────────────────────────────────────────────────────────
import re as _re

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "cwe": "CWE-319", "severity": "HIGH",
        "desc": "Allows protocol downgrade / MITM attacks",
        "good": lambda v: "max-age" in v and int((_re.search(r"max-age=(\d+)", v) or type("", (), {"group": lambda *a: "0"})()).group(1)) >= 31536000,
    },
    "Content-Security-Policy": {
        "cwe": "CWE-79", "severity": "MEDIUM",
        "desc": "Elevated XSS risk without CSP",
        "good": lambda v: len(v) > 20 and "unsafe-inline" not in v,
    },
    "X-Frame-Options": {
        "cwe": "CWE-1021", "severity": "MEDIUM",
        "desc": "Clickjacking attack surface",
        "good": lambda v: v.strip().upper() in ("DENY", "SAMEORIGIN"),
    },
    "X-Content-Type-Options": {
        "cwe": "CWE-116", "severity": "LOW",
        "desc": "MIME-type sniffing risk",
        "good": lambda v: v.strip().lower() == "nosniff",
    },
    "Referrer-Policy": {
        "cwe": "CWE-200", "severity": "LOW",
        "desc": "Referrer header may leak sensitive paths",
        "good": lambda v: any(x in v.lower() for x in ("no-referrer", "strict-origin", "same-origin")),
    },
    "Permissions-Policy": {
        "cwe": "CWE-276", "severity": "INFO",
        "desc": "Browser feature permissions unrestricted",
        "good": lambda v: len(v) > 5,
    },
    "X-XSS-Protection": {
        "cwe": "CWE-79", "severity": "INFO",
        "desc": "XSS Protection header absent or disabled",
        "good": lambda v: v.startswith("1"),
    },
    "Cache-Control": {
        "cwe": "CWE-524", "severity": "LOW",
        "desc": "Sensitive data may be cached by intermediaries",
        "good": lambda v: "no-store" in v or "private" in v,
    },
    "Cross-Origin-Opener-Policy": {
        "cwe": "CWE-346", "severity": "LOW",
        "desc": "Cross-origin window access not restricted (Spectre side-channel)",
        "good": lambda v: v.strip().lower() in ("same-origin", "same-origin-allow-popups"),
    },
    "Cross-Origin-Resource-Policy": {
        "cwe": "CWE-942", "severity": "LOW",
        "desc": "No cross-origin resource policy set",
        "good": lambda v: v.strip().lower() in ("same-origin", "same-site", "cross-origin"),
    },
}

# ── JS secret patterns ────────────────────────────────────────────────────────
JS_SECRET_PATTERNS = {
    "AWS Access Key":      r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":      r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Slack Token":         r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
    "GitHub Token":        r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "Private Key":         r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY",
    "Google API Key":      r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL":        r"https://[a-z0-9-]+\.firebaseio\.com",
    "Twilio SID":          r"AC[0-9a-fA-F]{32}",
    "Twilio Auth Token":   r"SK[0-9a-fA-F]{32}",
    "SendGrid Key":        r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "JWT Token":           r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Basic Auth in URL":   r"https?://[^/\s:@]{3,}:[^/\s:@]{3,}@[^/\s]+",
    "Stripe Live Key":     r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Key":     r"sk_test_[0-9a-zA-Z]{24,}",
    "Mailgun Key":         r"key-[0-9a-zA-Z]{32}",
    "Mailchimp Key":       r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Password in JS":      r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "API Key in JS":       r"(?i)api[_\-]?key\s*[:=]\s*['\"][^'\"]{10,}['\"]",
    "Bearer Token":        r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",
    "S3 Bucket URL":       r"https?://[a-z0-9\-\.]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com",
    "Internal IP":         r"(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}",
    "GraphQL Endpoint":    r"(?i)/graphql[\"'\s]|graphql.{0,5}endpoint",
    "Admin/Debug Path":    r"(?i)['\"/](?:admin|debug|console|test|dev|staging|internal|backdoor)['\"/]",
    "Hardcoded Secret":    r"(?i)(?:secret|token|auth|api)[_\-]?(?:key|token|secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "Azure Connection Str":r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+",
    "GCP Service Account": r"\"type\":\s*\"service_account\"",
    "Artifactory Token":   r"AKC[a-zA-Z0-9]{10,}",
}

# ── Cloud bucket detection ────────────────────────────────────────────────────
CLOUD_PROVIDERS = {
    "s3": {
        "url":       lambda b: f"https://{b}.s3.amazonaws.com",
        "not_exist": ["NoSuchBucket", "InvalidBucketName"],
        "public":    ["ListBucketResult", "<Contents>"],
        "exists":    ["AccessDenied", "AllAccessDisabled", "RequestTimeTooSkewed"],
    },
    "gcs": {
        "url":       lambda b: f"https://storage.googleapis.com/{b}",
        "not_exist": ["NoSuchBucket", "The specified bucket does not exist"],
        "public":    ["<Contents>", "<?xml"],
        "exists":    ["AccessDenied", "BucketNotPublic"],
    },
    "azure_blob": {
        "url":       lambda b: f"https://{b}.blob.core.windows.net",
        "not_exist": ["ResourceNotFound", "does not exist"],
        "public":    ["EnumerationResults", "<Blobs>"],
        "exists":    ["PublicAccessNotPermitted", "AuthorizationFailure", "InvalidAuthenticationInfo"],
    },
    "digitalocean": {
        "url":       lambda b: f"https://{b}.nyc3.digitaloceanspaces.com",
        "not_exist": ["NoSuchBucket"],
        "public":    ["ListBucketResult"],
        "exists":    ["AccessDenied"],
    },
}

# ── Subdomain wordlist ────────────────────────────────────────────────────────
SUBDOMAIN_WORDLIST = [
    "www","mail","ftp","webmail","smtp","pop","ns1","ns2","ns3","mx","api",
    "dev","staging","test","qa","uat","prod","beta","alpha","demo","sandbox",
    "admin","portal","dashboard","app","mobile","m","shop","store","blog",
    "support","help","helpdesk","forum","wiki","docs","documentation","kb",
    "git","gitlab","github","svn","bitbucket","jenkins","ci","cd","build",
    "jira","confluence","notion","trello","asana","slack","teams",
    "sso","auth","login","oauth","identity","account","accounts","my",
    "api","api-v1","api-v2","api-v3","rest","graphql","grpc","ws","websocket",
    "cdn","static","assets","media","images","img","files","download","uploads",
    "cloud","vpn","remote","access","connect","gateway","proxy","lb","edge",
    "db","database","mysql","mongo","redis","elastic","kibana","grafana",
    "internal","intranet","extranet","corp","corporate","employee","staff",
    "secure","ssl","tls","waf","firewall","ids","ips",
    "status","monitor","metrics","logs","logging","analytics","insights",
    "payment","pay","checkout","billing","invoice","finance","treasury",
    "v1","v2","v3","new","old","legacy","archive","backup","bak",
    "cpanel","whm","plesk","phpmyadmin","webmin","panel","control",
    "mail2","smtp2","relay","exchange","autodiscover","imap","pop3",
    "microservice","svc","service","worker","jobs","queue","tasks",
    "health","ping","heartbeat","alive","uptime",
    "ai","ml","model","predict","inference",
    "partner","affiliate","vendor","client","customer","b2b","b2c",
    "dev2","staging2","test2","uat2","preprod","pre-prod","preview",
]

# ── API endpoint wordlist ─────────────────────────────────────────────────────
API_WORDLIST = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/docs",
    "/health", "/healthz", "/health/live", "/health/ready", "/ping",
    "/metrics", "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/beans", "/actuator/info",
    "/.env", "/.git/config", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/security.txt",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/admin", "/admin/", "/admin/login", "/administrator", "/wp-admin",
    "/wp-login.php", "/wp-config.php", "/phpinfo.php", "/info.php",
    "/test.php", "/debug", "/console", "/shell", "/cmd",
    "/api/user", "/api/users", "/api/auth", "/api/login", "/api/token",
    "/api/refresh", "/api/profile", "/api/account", "/api/admin",
    "/api/config", "/api/settings", "/api/debug", "/api/internal",
    "/v1/user", "/v1/users", "/v1/auth", "/v1/login",
    "/v2/user", "/v2/users", "/v2/auth",
    "/.aws/credentials", "/.ssh/id_rsa", "/backup.sql", "/dump.sql",
    "/backup.zip", "/www.zip", "/source.zip", "/app.zip",
    "/server-status", "/server-info", "/status", "/info",
    "/trace", "/xmlrpc.php", "/CHANGELOG.md", "/VERSION",
    "/package.json", "/composer.json", "/requirements.txt", "/Gemfile",
    "/.DS_Store", "/thumbs.db", "/web.config", "/app.config",
    "/config.json", "/config.yml", "/config.yaml", "/settings.json",
    "/application.properties", "/application.yml", "/appsettings.json",
]
