"""shadowrecon/modules/mod_cloud_assets.py — Cloud bucket discovery."""

import concurrent.futures
from modules._constants import CLOUD_PROVIDERS
from modules._http import http_get, extract_root, company_name

BUCKET_SUFFIXES = [
    "", "-dev", "-prod", "-staging", "-test", "-uat", "-qa",
    "-backup", "-bak", "-data", "-media", "-assets", "-static",
    "-files", "-docs", "-images", "-uploads", "-public", "-private",
    "-internal", "-logs", "-archive", "-api", "-cdn", "-store",
    "-bucket", "-s3", "-gcs", "-blob", "-storage", "-dump",
    "-database", "-db", "-sql", "-backup-2023", "-backup-2024",
    ".dev", ".staging", ".prod", ".test",
]


def run(domain, args, out, state):
    result = {"found": [], "public": [], "issues": []}
    root    = extract_root(domain)
    company = company_name(domain)
    domain_dashed = root.replace(".", "-")

    # Generate permutations
    bases = list({company, root, domain_dashed,
                  company.replace("-", ""), company.replace("_", "")})
    permutations = set()
    for base in bases:
        for suffix in BUCKET_SUFFIXES:
            permutations.add(f"{base}{suffix}")

    out.info(f"Testing {len(permutations)} bucket names across {len(CLOUD_PROVIDERS)} providers ...")

    def check_bucket(name):
        hits = []
        for provider, cfg in CLOUD_PROVIDERS.items():
            url = cfg["url"](name)
            r   = http_get(url, timeout=5, allow_redirects=False)
            if not r:
                continue
            body   = r.text[:1000] if r.text else ""
            status = r.status_code

            not_exist = any(fp in body for fp in cfg["not_exist"])
            is_public = any(fp in body for fp in cfg["public"]) or status == 200
            is_exists = any(fp in body for fp in cfg["exists"]) or status in (400, 403)

            if not_exist or status == 404:
                continue
            elif is_public:
                hits.append({"provider": provider, "bucket": name,
                             "url": url, "status": "PUBLIC", "http": status})
            elif is_exists:
                hits.append({"provider": provider, "bucket": name,
                             "url": url, "status": "PRIVATE", "http": status})
        return hits

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, 10)) as ex:
        futures = {ex.submit(check_bucket, n): n for n in permutations}
        for f in concurrent.futures.as_completed(futures):
            hits = f.result()
            for hit in hits:
                result["found"].append(hit)
                if hit["status"] == "PUBLIC":
                    out.finding("CRITICAL",
                                f"PUBLIC BUCKET: {hit['url']} ({hit['provider']}) — unauthenticated listing!",
                                cwe="CWE-284", module="cloud_assets", url=hit["url"])
                    result["public"].append(hit)
                    result["issues"].append({"url": hit["url"], "severity": "CRITICAL",
                                             "cwe": "CWE-284", "desc": f"Public {hit['provider']} bucket: {hit['bucket']}"})
                else:
                    out.success(f"Bucket exists (private): {hit['url']} ({hit['provider']})")
                    out.info(f"  → Consider access key testing or misconfiguration audit")

    if not result["found"]:
        out.success("No cloud storage assets found for this target's naming patterns")
    else:
        out.info(f"Total cloud assets: {len(result['found'])} ({len(result['public'])} public)")
    return result
