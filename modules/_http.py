"""shadowrecon/modules/_http.py — Shared HTTP helpers with retry, sessions, proxy."""

import socket
import time
import threading
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings()

from modules._constants import HEADERS_DEFAULT

# ── Global rate-limiter ───────────────────────────────────────────────────────
_rate_lock         = threading.Lock()
_last_request_time = 0.0
_rate_limit_delay  = 0.05   # default 20 rps

# ── Session pool (one per thread for connection reuse) ────────────────────────
_thread_local = threading.local()

def _session() -> requests.Session:
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update(HEADERS_DEFAULT)
        adapter = requests.adapters.HTTPAdapter(
            max_retries=urllib3.util.retry.Retry(
                total=2,
                backoff_factor=0.4,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "POST", "OPTIONS"],
                raise_on_status=False,
            )
        )
        s.mount("http://",  adapter)
        s.mount("https://", adapter)
        _thread_local.session = s
    return _thread_local.session


def set_rate_limit(rps: float):
    global _rate_limit_delay
    _rate_limit_delay = 1.0 / max(rps, 0.1)


def _throttle():
    global _last_request_time
    with _rate_lock:
        elapsed = time.time() - _last_request_time
        if elapsed < _rate_limit_delay:
            time.sleep(_rate_limit_delay - elapsed)
        _last_request_time = time.time()


def http_get(
    url: str,
    timeout: int = 8,
    allow_redirects: bool = True,
    verify: bool = False,
    extra_headers: dict = None,
    proxies: dict = None,
) -> Optional[requests.Response]:
    _throttle()
    headers = dict(HEADERS_DEFAULT)
    if extra_headers:
        headers.update(extra_headers)
    try:
        sess = _session()
        r = sess.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            proxies=proxies,
        )
        return r
    except requests.exceptions.SSLError:
        # Retry without verify on SSL errors
        try:
            return requests.get(url, headers=headers, timeout=timeout,
                                allow_redirects=allow_redirects,
                                verify=False, proxies=proxies)
        except Exception:
            return None
    except Exception:
        return None


def http_request(
    method: str,
    url: str,
    timeout: int = 8,
    verify: bool = False,
    extra_headers: dict = None,
    data=None,
    json=None,
    proxies: dict = None,
) -> Optional[requests.Response]:
    _throttle()
    headers = dict(HEADERS_DEFAULT)
    if extra_headers:
        headers.update(extra_headers)
    try:
        r = requests.request(
            method, url,
            headers=headers,
            timeout=timeout,
            verify=verify,
            data=data,
            json=json,
            allow_redirects=False,
            proxies=proxies,
        )
        return r
    except Exception:
        return None


def http_head(url: str, timeout: int = 5) -> Optional[requests.Response]:
    _throttle()
    try:
        return requests.head(url, headers=dict(HEADERS_DEFAULT),
                             timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return None


def resolve(domain: str) -> list[str]:
    """Return list of unique IPv4 addresses for domain."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        seen, ips = set(), []
        for r in results:
            ip = str(r[4][0])
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips
    except Exception:
        return []


def extract_root(domain: str) -> str:
    try:
        import tldextract
        e = tldextract.extract(domain)
        return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else domain
    except Exception:
        parts = domain.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def company_name(domain: str) -> str:
    return extract_root(domain).split(".")[0]


def is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False
