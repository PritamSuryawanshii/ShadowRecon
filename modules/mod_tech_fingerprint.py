"""shadowrecon/modules/mod_tech_fingerprint.py — Technology stack detection."""

import re
from modules._http import http_get

# (regex_on_body_or_headers, category, name)
TECH_SIGNATURES = [
    # CMS
    (r"wp-content|wp-includes|/wp-json/|wordpress",                    "CMS",         "WordPress"),
    (r"drupal\.js|drupal\.settings|sites/default/files|Drupal",        "CMS",         "Drupal"),
    (r"/media/jui/|/components/com_|Joomla",                           "CMS",         "Joomla"),
    (r"shopify|cdn\.shopify\.com|myshopify\.com",                      "eCommerce",   "Shopify"),
    (r"/skin/frontend/|mage/|Magento",                                 "eCommerce",   "Magento"),
    (r"woocommerce|wc-api|woocommerce_session",                        "eCommerce",   "WooCommerce"),
    (r"prestashop|/modules/blockcart",                                 "eCommerce",   "PrestaShop"),
    # Frameworks / languages
    (r"laravel_session|X-Laravel|laravel",                             "Framework",   "Laravel (PHP)"),
    (r"csrfmiddlewaretoken|/static/admin/|django",                     "Framework",   "Django (Python)"),
    (r"_rails|X-Runtime.*Ruby|on Ruby|rails",                          "Framework",   "Ruby on Rails"),
    (r"X-Powered-By.*Express|expressjs",                               "Framework",   "Express.js (Node)"),
    (r"X-Powered-By.*Next\.js|__NEXT_DATA__|_next/static",             "Framework",   "Next.js"),
    (r"__nuxt__|_nuxt/|nuxt",                                          "Framework",   "Nuxt.js"),
    (r"X-Powered-By.*ASP\.NET|__VIEWSTATE|\.aspx|\.ashx",             "Runtime",     "ASP.NET"),
    (r"X-Powered-By.*PHP|PHPSESSID|\.php",                            "Runtime",     "PHP"),
    (r"spring|X-Application-Context|tomcat",                          "Framework",   "Spring (Java)"),
    (r"struts|org\.apache\.struts",                                    "Framework",   "Apache Struts"),
    # Frontend
    (r"react\.development\.js|__reactfiber|__react|\"react\":",        "Frontend",    "React"),
    (r"ng-version|angular\.min\.js|ng-app|angular/core",               "Frontend",    "Angular"),
    (r"__vue__|vue\.runtime\.min\.js|\"vue\":",                        "Frontend",    "Vue.js"),
    (r"ember\.js|Ember\.VERSION",                                      "Frontend",    "Ember.js"),
    (r"backbone\.js|Backbone\.",                                       "Frontend",    "Backbone.js"),
    (r"svelte|__svelte",                                               "Frontend",    "Svelte"),
    (r"jquery[\.\-][\d\.]+\.min\.js|jQuery\.fn\.jquery",              "Library",     "jQuery"),
    (r"bootstrap\.min\.css|bootstrap\.bundle",                         "UI",          "Bootstrap"),
    (r"tailwindcss|tailwind",                                          "UI",          "Tailwind CSS"),
    (r"material-ui|@mui/",                                             "UI",          "Material UI"),
    # API / protocols
    (r"graphql|\"__schema\"",                                          "API",         "GraphQL"),
    (r"swagger-ui|openapi\.json|api-docs|swagger\.json",              "API",         "Swagger/OpenAPI"),
    (r"\"jsonrpc\":\s*\"2\.0\"",                                       "API",         "JSON-RPC"),
    (r"wsdl|soap:Envelope|xmlns:soap",                                 "API",         "SOAP/WSDL"),
    # Databases / search
    (r"elasticsearch|\"hits\":\s*\{\"total\"",                        "Database",    "Elasticsearch"),
    (r"mongodb",                                                       "Database",    "MongoDB"),
    (r"redis",                                                         "Database",    "Redis"),
    (r"sql server|mssql|sqlexception",                                 "Database",    "MSSQL"),
    # CDN / WAF / proxy
    (r"cf-ray|cloudflare",                                             "CDN",         "Cloudflare"),
    (r"x-amz-cf-id|cloudfront\.net",                                  "CDN",         "AWS CloudFront"),
    (r"x-akamai-transformed",                                          "CDN",         "Akamai"),
    (r"x-fastly-request-id",                                           "CDN",         "Fastly"),
    # Auth / identity
    (r"keycloak|/auth/realms/",                                        "Auth",        "Keycloak"),
    (r"okta|okta\.com",                                                "Auth",        "Okta"),
    (r"auth0|cdn\.auth0\.com",                                         "Auth",        "Auth0"),
    (r"cognito|amazon\.com/cognito",                                   "Auth",        "AWS Cognito"),
    # Observability
    (r"datadog|datadoghq\.com",                                        "Observability","Datadog"),
    (r"sentry\.io|Sentry\.init",                                       "Observability","Sentry"),
    (r"newrelic|New Relic",                                            "Observability","New Relic"),
    (r"splunk",                                                        "Observability","Splunk"),
    # Payments
    (r"stripe\.js|stripe\.com/v3",                                     "Payments",    "Stripe"),
    (r"paypal\.com/sdk",                                               "Payments",    "PayPal"),
    (r"braintree|braintreegateway",                                    "Payments",    "Braintree"),
    # Marketing
    (r"google-analytics\.com|gtag\(|UA-\d{4,}",                       "Analytics",   "Google Analytics"),
    (r"segment\.com|analytics\.js",                                    "Analytics",   "Segment"),
    (r"hotjar",                                                        "Analytics",   "Hotjar"),
    (r"intercom\.io",                                                  "CRM",         "Intercom"),
    (r"hubspot|hs-scripts\.com",                                       "CRM",         "HubSpot"),
    # Cloud hosting
    (r"x-amzn-requestid|aws-us-east",                                  "Cloud",       "AWS"),
    (r"x-ms-request-id|azurewebsites\.net",                           "Cloud",       "Azure"),
    (r"x-goog-request-id|cloud\.google\.com",                         "Cloud",       "GCP"),
    (r"vercel|x-vercel-id",                                            "Cloud",       "Vercel"),
    (r"netlify|x-nf-request-id",                                       "Cloud",       "Netlify"),
    (r"heroku|x-request-id.*heroku",                                   "Cloud",       "Heroku"),
]

# Server version disclosure patterns
VERSION_PATTERNS = [
    (r"Apache/(\d[\d\.]+)",          "Apache",       "CWE-200"),
    (r"nginx/(\d[\d\.]+)",           "Nginx",        "CWE-200"),
    (r"Microsoft-IIS/(\d[\d\.]+)",   "IIS",          "CWE-200"),
    (r"PHP/(\d[\d\.]+)",             "PHP",          "CWE-200"),
    (r"OpenSSL/(\d[\d\.]+)",         "OpenSSL",      "CWE-200"),
    (r"Tomcat/(\d[\d\.]+)",          "Tomcat",       "CWE-200"),
    (r"JBoss/(\d[\d\.]+)",           "JBoss",        "CWE-200"),
    (r"WebLogic (\d[\d\.]+)",        "WebLogic",     "CWE-200"),
    (r"Python/(\d[\d\.]+)",          "Python",       "CWE-200"),
    (r"Ruby/(\d[\d\.]+)",            "Ruby",         "CWE-200"),
]


def run(domain, args, out, state):
    result = {"technologies": {}, "versions": {}, "issues": []}

    for scheme in ("https", "http"):
        r = http_get(f"{scheme}://{domain}", timeout=args.timeout)
        if r:
            break
    if not r:
        out.fail("Cannot reach target")
        return result

    body     = r.text or ""
    body_l   = body.lower()
    hdr_str  = " ".join(f"{k}: {v}" for k, v in r.headers.items())
    combined = body_l + " " + hdr_str.lower()

    # ── Technology detection ──────────────────────────────────────────────────
    detected = {}
    for pattern, category, name in TECH_SIGNATURES:
        if re.search(pattern, combined, re.IGNORECASE):
            if name not in detected:
                detected[name] = category
                out.success(f"[{category:14s}] {name}")

    result["technologies"] = detected
    state.technologies = detected

    # ── Version disclosure ────────────────────────────────────────────────────
    server_hdr  = r.headers.get("Server", "")
    powered_hdr = r.headers.get("X-Powered-By", "")
    all_hdr_str = server_hdr + " " + powered_hdr + " " + hdr_str

    for pattern, product, cwe in VERSION_PATTERNS:
        m = re.search(pattern, all_hdr_str, re.IGNORECASE)
        if m:
            ver = m.group(1)
            out.finding("MEDIUM",
                        f"Version disclosed in HTTP headers: {product}/{ver} — enables targeted CVE lookup",
                        cwe=cwe, module="tech_fingerprint")
            result["versions"][product] = ver
            result["issues"].append({
                "severity": "MEDIUM", "cwe": cwe,
                "desc": f"Version disclosed: {product}/{ver}"
            })

    # ── Cookie-based tech fingerprinting ─────────────────────────────────────
    cookie_tech = {
        "PHPSESSID":          "PHP session",
        "JSESSIONID":         "Java/Tomcat session",
        "ASP.NET_SessionId":  "ASP.NET session",
        "laravel_session":    "Laravel (PHP)",
        "rack.session":       "Ruby/Rack",
        "_session_id":        "Rails session",
        "django_language":    "Django",
        "csrftoken":          "Django CSRF",
    }
    for cookie_name, tech_name in cookie_tech.items():
        if cookie_name.lower() in {c.lower() for c in r.cookies.keys()}:
            if tech_name not in detected:
                out.info(f"Cookie fingerprint: {tech_name} (via {cookie_name})")
                result["technologies"][tech_name] = "Cookie"

    # ── HTML meta generator ───────────────────────────────────────────────────
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                  body, re.IGNORECASE)
    if m:
        gen = m.group(1)
        out.finding("LOW", f"Generator meta tag: {gen} — CMS/version disclosure",
                    cwe="CWE-200", module="tech_fingerprint")
        result["technologies"]["Generator"] = gen
        result["issues"].append({
            "severity": "LOW", "cwe": "CWE-200",
            "desc": f"Generator tag: {gen}"
        })

    # ── robots.txt scrape ─────────────────────────────────────────────────────
    r_robots = http_get(f"https://{domain}/robots.txt", timeout=args.timeout)
    if r_robots and r_robots.status_code == 200 and "Disallow" in r_robots.text:
        disallowed = re.findall(r"Disallow:\s*(\S+)", r_robots.text)
        if disallowed:
            out.info(f"robots.txt: {len(disallowed)} disallowed paths (attack surface hints):")
            for path in disallowed[:15]:
                out.kv("  Disallow", path)
            result["robots_disallow"] = disallowed

    out.info(f"Technologies identified: {len(detected)}")
    return result
