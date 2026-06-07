"""shadowrecon/modules/mod_graphql.py — GraphQL introspection & batch detection."""

import json
from modules._http import http_request, http_get

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
                 "/query", "/gql", "/api/query", "/api/gql", "/graphiql",
                 "/playground", "/altair"]

INTROSPECTION_QUERY = {
    "query": "{ __schema { queryType { name } types { name kind } } }"
}

FULL_INTROSPECTION = {
    "query": """
    { __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
            name kind description
            fields { name description
                args { name description type { name kind ofType { name kind } } }
                type { name kind ofType { name kind } }
            }
        }
    }}"""
}

BATCH_QUERY = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]

FIELD_SUGGESTION_QUERY = {"query": "{ __typenme }"}  # intentional typo


def _post_graphql(url, payload, timeout):
    return http_request("POST", url, timeout=timeout,
                        extra_headers={"Content-Type": "application/json"},
                        json=payload)


def run(domain, args, out, state):
    result = {"endpoints": [], "exposed_types": [], "issues": []}

    targets = [f"https://{domain}"]
    for s in state.subdomains[:8]:
        targets.append(f"https://{s['host']}")

    found_gql_urls = []

    for base in targets:
        for path in GRAPHQL_PATHS:
            url = base.rstrip("/") + path

            # Quick GET probe first
            r = http_get(url, timeout=args.timeout)
            if not r or r.status_code in (404,):
                continue

            # POST introspection
            r_intro = _post_graphql(url, INTROSPECTION_QUERY, args.timeout)
            if not r_intro:
                continue

            if r_intro.status_code in (200, 201):
                try:
                    data = r_intro.json()
                    if "data" in data or "__schema" in str(data):
                        found_gql_urls.append(url)
                        out.finding("HIGH",
                                    f"GraphQL introspection ENABLED on {url} — full schema exposed",
                                    cwe="CWE-200", module="graphql", url=url)
                        result["issues"].append({"url": url, "severity": "HIGH",
                                                 "cwe": "CWE-200", "desc": "GraphQL introspection enabled"})
                        result["endpoints"].append(url)

                        # Full schema dump
                        r_full = _post_graphql(url, FULL_INTROSPECTION, args.timeout)
                        if r_full and r_full.status_code == 200:
                            try:
                                schema = r_full.json()
                                types = schema.get("data", {}).get("__schema", {}).get("types", [])
                                user_types = [t for t in types
                                              if t.get("name") and not t["name"].startswith("__")]
                                out.info(f"  Schema has {len(user_types)} types")
                                for t in user_types[:20]:
                                    out.kv(f"  Type", f"{t['name']} ({t.get('kind','')})")
                                    result["exposed_types"].append(t["name"])
                                # Flag sensitive types
                                sensitive_kw = ["user", "admin", "password", "token", "secret",
                                                "auth", "payment", "credit", "private", "internal"]
                                for t in user_types:
                                    if any(kw in t["name"].lower() for kw in sensitive_kw):
                                        out.finding("HIGH",
                                                    f"Sensitive GraphQL type exposed: {t['name']}",
                                                    cwe="CWE-200", module="graphql", url=url)
                            except Exception:
                                pass
                except Exception:
                    pass

            # Field suggestion check (typo in field name)
            r_sugg = _post_graphql(url, FIELD_SUGGESTION_QUERY, args.timeout)
            if r_sugg and r_sugg.text and "Did you mean" in r_sugg.text:
                out.finding("MEDIUM",
                            f"GraphQL field suggestions ENABLED on {url} — schema inference possible without introspection",
                            cwe="CWE-200", module="graphql", url=url)
                result["issues"].append({"url": url, "severity": "MEDIUM",
                                         "cwe": "CWE-200", "desc": "Field suggestions enabled"})

            # Batch attack probe (DoS / rate-limit bypass)
            r_batch = _post_graphql(url, BATCH_QUERY, args.timeout)
            if r_batch and r_batch.status_code == 200:
                try:
                    batch_resp = r_batch.json()
                    if isinstance(batch_resp, list) and len(batch_resp) == 3:
                        out.finding("MEDIUM",
                                    f"GraphQL batch queries ENABLED on {url} — DoS / rate-limit bypass possible",
                                    cwe="CWE-770", module="graphql", url=url)
                        result["issues"].append({"url": url, "severity": "MEDIUM",
                                                 "cwe": "CWE-770", "desc": "Batch queries enabled"})
                except Exception:
                    pass

    if not found_gql_urls:
        out.success("No accessible GraphQL endpoints detected")

    return result
