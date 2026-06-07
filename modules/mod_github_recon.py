"""shadowrecon/modules/mod_github_recon.py — GitHub org & secret recon."""

import time
import re
import requests
from modules._constants import HEADERS_DEFAULT
from modules._http import extract_root, company_name, http_get

# Keywords that trigger a code-search sweep
SECRET_QUERIES = [
    "password", "api_key", "secret_key", "AWS_SECRET", "private_key",
    "access_token", "auth_token", "BEGIN RSA", "client_secret",
]

SENSITIVE_FILE_PATTERNS = [
    r"\.env$", r"\.pem$", r"\.key$", r"id_rsa", r"credentials",
    r"config\.yml$", r"secrets\.yml$", r"database\.yml$",
    r"settings\.py$", r"\.aws/credentials", r"docker-compose\.yml$",
]


def _gh_headers(token: str | None) -> dict:
    h = dict(HEADERS_DEFAULT)
    h["Accept"] = "application/vnd.github+json"
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _gh_get(url: str, token, timeout: int):
    try:
        r = requests.get(url, headers=_gh_headers(token), timeout=timeout)
        return r
    except Exception:
        return None


def _rate_pause(r):
    """Respect GitHub rate-limit headers."""
    if r is None:
        return
    remaining = int(r.headers.get("X-RateLimit-Remaining", 9999))
    if remaining < 5:
        reset = int(r.headers.get("X-RateLimit-Reset", 0))
        import time as _t
        wait = max(0, reset - _t.time()) + 2
        time.sleep(min(wait, 30))
    else:
        time.sleep(0.3)


def run(domain, args, out, state):
    result = {"org": None, "repos": [], "secrets": [], "leaks": [], "issues": []}
    token   = args.github_token
    timeout = args.timeout
    root    = extract_root(domain)
    company = company_name(domain)

    if not token:
        out.warn("No --github-token supplied — using unauthenticated API (60 req/hr limit)")

    # ── 1. Org lookup ─────────────────────────────────────────────────────────
    out.info(f"Looking up GitHub org '{company}' ...")
    r = _gh_get(f"https://api.github.com/orgs/{company}", token, timeout)
    _rate_pause(r)

    if r and r.status_code == 200:
        org = r.json()
        result["org"] = {
            "login":        org.get("login"),
            "name":         org.get("name"),
            "public_repos": org.get("public_repos", 0),
            "followers":    org.get("followers", 0),
            "blog":         org.get("blog", ""),
            "location":     org.get("location", ""),
            "email":        org.get("email", ""),
        }
        out.success(f"Org found: {org.get('login')}  "
                    f"({org.get('public_repos',0)} public repos, "
                    f"{org.get('followers',0)} followers)")
        out.kv("Blog",     org.get("blog", "-"))
        out.kv("Location", org.get("location", "-"))
        if org.get("email"):
            out.kv("Email", org["email"])

        # ── 2. List public repos (sorted by most-recently-pushed) ──────────
        out.info("Fetching public repositories ...")
        r2 = _gh_get(
            f"https://api.github.com/orgs/{company}/repos?per_page=100&sort=pushed&type=public",
            token, timeout
        )
        _rate_pause(r2)
        if r2 and r2.status_code == 200:
            repos = r2.json()
            for repo in repos[:50]:
                rname   = repo.get("full_name", "")
                lang    = repo.get("language") or "?"
                pushed  = (repo.get("pushed_at") or "")[:10]
                stars   = repo.get("stargazers_count", 0)
                forks   = repo.get("forks_count", 0)
                desc_r  = repo.get("description") or ""
                default = repo.get("default_branch", "main")
                entry   = {"name": rname, "lang": lang, "pushed": pushed,
                           "stars": stars, "forks": forks, "branch": default}
                result["repos"].append(entry)
                out.kv("Repo", f"{rname}  [{lang}]  ★{stars}  pushed {pushed}")
                if desc_r:
                    out.debug(f"  {desc_r}")

                # Sensitive file check via repo tree
                _check_repo_tree(rname, default, token, timeout, out, result)

    else:
        out.info(f"No public org '{company}' found (HTTP {r.status_code if r else 'timeout'})")

    # ── 3. Code search — secrets referencing this domain ─────────────────────
    out.info(f"Searching GitHub code for '{domain}' references ...")
    _code_search(domain, company, root, token, timeout, out, result, args)

    # ── 4. Gist search ────────────────────────────────────────────────────────
    out.info(f"Searching public gists for '{domain}' ...")
    try:
        r_gist = _gh_get(
            f"https://api.github.com/search/code?q={domain}+in:file&type=gist",
            token, timeout
        )
        _rate_pause(r_gist)
        if r_gist and r_gist.status_code == 200:
            items = r_gist.json().get("items", [])
            for item in items[:5]:
                out.finding("MEDIUM",
                            f"Domain referenced in public gist: {item.get('html_url','')}",
                            cwe="CWE-200", module="github_recon")
                result["leaks"].append({"type": "gist", "url": item.get("html_url","")})
    except Exception:
        pass

    out.info(f"GitHub recon: {len(result['repos'])} repos, "
             f"{len(result['secrets'])} secret hits, "
             f"{len(result['leaks'])} leaks")
    return result


def _check_repo_tree(repo_name: str, branch: str, token, timeout: int, out, result):
    """Fetch repo tree and flag sensitive filenames."""
    r = _gh_get(
        f"https://api.github.com/repos/{repo_name}/git/trees/{branch}?recursive=1",
        token, timeout
    )
    _rate_pause(r)
    if not r or r.status_code != 200:
        return
    tree = r.json().get("tree", [])
    for item in tree:
        path = item.get("path", "")
        for pat in SENSITIVE_FILE_PATTERNS:
            if re.search(pat, path, re.IGNORECASE):
                url = f"https://github.com/{repo_name}/blob/{branch}/{path}"
                out.finding("HIGH",
                            f"Sensitive file in repo {repo_name}: {path}",
                            cwe="CWE-538", module="github_recon", url=url)
                result["secrets"].append({
                    "repo": repo_name, "file": path, "url": url, "type": "sensitive_file"
                })
                result["issues"].append({
                    "severity": "HIGH", "cwe": "CWE-538",
                    "desc": f"Sensitive file: {repo_name}/{path}"
                })


def _code_search(domain, company, root, token, timeout, out, result, args):
    queries = [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'"{company}" AWS_SECRET_ACCESS_KEY',
        f'"{company}" private_key',
        f'"{root}" token',
    ]
    for query in queries:
        r = _gh_get(
            f"https://api.github.com/search/code?q={requests.utils.quote(query)}&per_page=10",
            token, timeout
        )
        _rate_pause(r)
        if not r:
            continue
        if r.status_code == 403:
            out.warn("GitHub code search rate-limited — provide --github-token for higher limits")
            break
        if r.status_code != 200:
            continue
        items = r.json().get("items", [])
        for item in items[:5]:
            file_url = item.get("html_url", "")
            repo     = item.get("repository", {}).get("full_name", "")
            path     = item.get("path", "")
            out.finding("HIGH",
                        f"Secret-keyword match [{query.split()[1]}] in {repo}/{path}",
                        cwe="CWE-312", module="github_recon", url=file_url)
            result["secrets"].append({
                "query": query, "repo": repo, "file": path,
                "url": file_url, "type": "code_search"
            })
            result["issues"].append({
                "severity": "HIGH", "cwe": "CWE-312",
                "desc": f"Secret keyword hit: {repo}/{path}"
            })
        time.sleep(0.5)
