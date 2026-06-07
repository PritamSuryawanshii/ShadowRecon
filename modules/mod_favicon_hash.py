"""shadowrecon/modules/mod_favicon_hash.py — Favicon MurmurHash fingerprinting."""

import base64
import re
import struct
import mmh3  # optional; gracefully fallback if missing
from modules._http import http_get

# Known favicon hashes → product name (Shodan/FOFA style)
KNOWN_HASHES = {
    -1290507574:  "WordPress default",
    116323821:    "Cisco Web UI",
    -1506647805:  "Jira / Atlassian",
    1471085966:   "Jenkins",
    1428808735:   "GitLab",
    -1220813816:  "Kibana",
    -2107852652:  "Grafana",
    -1439988534:  "Prometheus",
    1498544082:   "Jupyter Notebook",
    -1826651662:  "Fortinet / FortiGate",
    -923717534:   "F5 BIG-IP",
    -1429048477:  "Citrix Gateway",
    1776586977:   "VMware vSphere",
    -482312631:   "pfSense",
    1079462315:   "Outlook Web Access (OWA)",
    -1268958756:  "SharePoint",
    2029841928:   "NetScaler / Citrix ADC",
    -447334892:   "SolarWinds",
    -1422924949:  "phpMyAdmin",
    1024559481:   "Webmin",
    116476902:    "Plesk",
    -1613682899:  "cPanel",
    -1360239673:  "ZoHo",
    1423071224:   "ManageEngine",
    -1579828020:  "Keycloak",
    1322950611:   "Harbor (container registry)",
    -1548574536:  "Rancher",
    -2014601394:  "Portainer",
    -1890230128:  "Traefik",
    1281308218:   "Apache default page",
    1714576319:   "Nginx default page",
    1178975494:   "IIS default page",
    -2121681809:  "Tomcat Manager",
    -1292743051:  "Spring Boot",
    -1890830591:  "Laravel",
    -2059452521:  "Django admin",
    2026834605:   "Magento 2",
    -297068954:   "PrestaShop",
    -1502444073:  "Drupal",
    1192436284:   "Joomla",
    1782210397:   "TYPO3",
    -1874988558:  "Shopify",
    1775975125:   "Strapi",
    -836491753:   "Ghost CMS",
    -1988459726:  "Rocket.Chat",
    1543016719:   "Mattermost",
    -1413474528:  "GitBook",
    2142440062:   "Confluence",
    1085864290:   "Bitbucket",
    -1453765730:  "SonarQube",
    -698508905:   "Nexus Repository",
    -615526777:   "Artifactory",
    -247549276:   "Swagger UI",
    -1588092987:  "Metabase",
    -1700872544:  "Apache Airflow",
    1277644436:   "MinIO",
    -1019059785:  "Vault (HashiCorp)",
    -1268944340:  "Consul",
    -1987929823:  "Redis Commander",
    -849994600:   "MongoDB Express",
    -1726847985:  "Elasticsearch (Cerebro)",
    -1609001184:  "PgAdmin",
    1576836986:   "PhpPgAdmin",
    -1219401671:  "Adminer",
    1097220628:   "RabbitMQ Management",
    -1600926573:  "Apache Kafka (Kafdrop)",
    -2018588158:  "Zabbix",
    1466956474:   "Nagios",
    -1143599130:  "Icinga",
    -786169933:   "Graylog",
    1578390625:   "ELK Stack",
    1145879092:   "Splunk Web",
    -600498703:   "Datadog",
    -1836745718:  "New Relic",
    2049539618:   "PagerDuty",
    -1641390965:  "OPNsense",
    -1032823811:  "MikroTik RouterOS",
    -1618423218:  "Ubiquiti UniFi",
    1145218194:   "Netgear",
    -1034793810:  "D-Link router",
    -1589574133:  "TP-Link",
    -619478543:   "QNAP NAS",
    1297111756:   "Synology NAS",
    -1581288494:  "HIKVISION DVR/NVR",
    1736644069:   "Dahua DVR/NVR",
}


def _mmh3_hash(data: bytes) -> int:
    """MurmurHash3 32-bit signed — same as Shodan's favicon hash."""
    try:
        return mmh3.hash(data)
    except Exception:
        # Pure-Python fallback (simplified MurmurHash3 x86_32)
        return _mmh3_fallback(data)


def _mmh3_fallback(data: bytes) -> int:
    """Minimal pure-Python MurmurHash3 x86_32 for when mmh3 is absent."""
    seed  = 0
    c1    = 0xcc9e2d51
    c2    = 0x1b873593
    h1    = seed
    length = len(data)
    remainder = length & 3
    bytes_   = length - remainder

    for i in range(0, bytes_, 4):
        k1 = struct.unpack("<I", data[i:i+4])[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = ((h1 * 5) + 0xe6546b64) & 0xFFFFFFFF

    if remainder:
        tail = data[bytes_:]
        k1   = 0
        for j in range(remainder - 1, -1, -1):
            k1 = (k1 << 8) | tail[j]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Convert to signed 32-bit
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def _get_favicon_url(domain: str, base_url: str, html: str) -> str | None:
    """Find favicon URL from link tags or return default /favicon.ico."""
    m = re.search(
        r'<link[^>]+rel=["\'](?:shortcut\s+)?icon["\'][^>]+href=["\']([^"\']+)["\']',
        html, re.IGNORECASE
    )
    if not m:
        m = re.search(
            r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut\s+)?icon["\']',
            html, re.IGNORECASE
        )
    if m:
        href = m.group(1)
        if href.startswith("http"):
            return href
        elif href.startswith("//"):
            return "https:" + href
        elif href.startswith("/"):
            return base_url + href
        else:
            return base_url + "/" + href
    return f"https://{domain}/favicon.ico"


def run(domain, args, out, state):
    result = {"favicon_url": None, "hash": None, "known_product": None, "issues": []}

    # Fetch main page to find favicon URL
    r = http_get(f"https://{domain}", timeout=args.timeout)
    if not r:
        out.fail("Cannot reach target for favicon fetch")
        return result

    favicon_url = _get_favicon_url(domain, f"https://{domain}", r.text or "")
    result["favicon_url"] = favicon_url
    out.info(f"Favicon URL: {favicon_url}")

    # Fetch favicon bytes
    r_fav = http_get(favicon_url, timeout=args.timeout)
    if not r_fav or not r_fav.content:
        out.fail("Favicon not found or empty")
        return result

    raw_bytes = r_fav.content

    # Shodan-style: base64-encode → hash the b64 string
    b64_encoded = base64.encodebytes(raw_bytes)
    favicon_hash = _mmh3_hash(b64_encoded)
    result["hash"] = favicon_hash

    out.kv("Favicon size",    f"{len(raw_bytes)} bytes")
    out.kv("MurmurHash3",     str(favicon_hash))
    out.kv("Shodan search",   f"https://www.shodan.io/search?query=http.favicon.hash:{favicon_hash}")
    out.kv("FOFA search",     f'https://fofa.info/result?qbase64={base64.b64encode(f"icon_hash={favicon_hash}".encode()).decode()}')

    # Lookup in known-hash DB
    known = KNOWN_HASHES.get(favicon_hash)
    if known:
        out.finding("INFO",
                    f"Favicon fingerprint matches: [bold]{known}[/bold] — confirm product version & CVEs",
                    module="favicon_hash")
        result["known_product"] = known
        result["issues"].append({
            "severity": "INFO",
            "desc": f"Favicon fingerprint: {known} (hash: {favicon_hash})"
        })
    else:
        out.info("Favicon hash not in local database — search Shodan/FOFA manually with the hash above")

    return result
