"""shadowrecon/modules/mod_email_security.py — SPF/DKIM/DMARC/BIMI/MTA-STS."""

import dns.resolver


DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "s1", "s2", "k1",
    "email", "selector1", "selector2", "mandrill", "sendgrid",
    "mailgun", "postmark", "amazonses", "zoho", "protonmail",
    "smtp", "key1", "key2", "mimecast", "mailchimp",
]


def run(domain, args, out, state):
    result = {"spf": None, "dmarc": None, "dkim": [], "bimi": None, "mta_sts": None, "issues": []}
    resolver = dns.resolver.Resolver()
    resolver.timeout  = args.timeout
    resolver.lifetime = args.timeout

    # ── SPF ───────────────────────────────────────────────────────────────────
    out.info("Checking SPF ...")
    try:
        answers = resolver.resolve(domain, "TXT")
        spf_records = []
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith("v=spf1"):
                spf_records.append(txt)

        if not spf_records:
            out.finding("HIGH", "No SPF record — email spoofing trivially possible",
                        cwe="CWE-290", module="email_security")
            result["issues"].append({"type": "SPF", "severity": "HIGH", "cwe": "CWE-290",
                                     "desc": "Missing SPF"})
        elif len(spf_records) > 1:
            out.finding("MEDIUM", f"Multiple SPF records ({len(spf_records)}) — undefined behaviour, delivery issues",
                        cwe="CWE-290", module="email_security")
            result["issues"].append({"type": "SPF", "severity": "MEDIUM", "cwe": "CWE-290",
                                     "desc": "Multiple SPF records"})
        else:
            spf = spf_records[0]
            result["spf"] = spf
            out.kv("SPF", spf)
            if "+all" in spf:
                out.finding("CRITICAL", "SPF +all — ANY server can send as this domain!",
                            cwe="CWE-290", module="email_security")
                result["issues"].append({"type": "SPF", "severity": "CRITICAL", "cwe": "CWE-290",
                                         "desc": "+all mechanism"})
            elif "?all" in spf:
                out.finding("HIGH", "SPF ?all — neutral result, spoofing allowed",
                            cwe="CWE-290", module="email_security")
            elif "~all" in spf:
                out.finding("LOW", "SPF ~all (softfail) — spoofing may succeed at permissive receivers",
                            cwe="CWE-290", module="email_security")
            elif "-all" in spf:
                out.success("SPF hardened: -all (reject)")
            # Count DNS lookups (max 10 per RFC)
            lookup_mechanisms = [m for m in spf.split() if m.startswith(("include:", "a:", "mx:", "ptr:", "exists:"))]
            if len(lookup_mechanisms) > 9:
                out.finding("LOW", f"SPF has {len(lookup_mechanisms)} DNS lookups — exceeds RFC limit of 10, SPF may permerror",
                            cwe="CWE-290", module="email_security")
    except Exception:
        out.finding("HIGH", "Cannot retrieve TXT records for SPF check",
                    cwe="CWE-290", module="email_security")

    # ── DMARC ─────────────────────────────────────────────────────────────────
    out.info("Checking DMARC ...")
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith("v=DMARC1"):
                result["dmarc"] = txt
                out.kv("DMARC", txt)
                if "p=none" in txt:
                    out.finding("MEDIUM", "DMARC p=none — monitoring only, not enforced",
                                cwe="CWE-290", module="email_security")
                    result["issues"].append({"type": "DMARC", "severity": "MEDIUM", "cwe": "CWE-290",
                                             "desc": "p=none"})
                elif "p=quarantine" in txt:
                    out.finding("LOW", "DMARC p=quarantine — partial enforcement",
                                cwe="CWE-290", module="email_security")
                elif "p=reject" in txt:
                    out.success("DMARC fully enforced: p=reject")
                # Check rua (reporting)
                if "rua=" not in txt:
                    out.finding("INFO", "DMARC has no rua= (aggregate report) destination",
                                cwe="CWE-200", module="email_security")
    except dns.resolver.NXDOMAIN:
        out.finding("HIGH", "No DMARC record — no spoofing enforcement",
                    cwe="CWE-290", module="email_security")
        result["issues"].append({"type": "DMARC", "severity": "HIGH", "cwe": "CWE-290",
                                 "desc": "Missing DMARC"})
    except Exception:
        pass

    # ── DKIM ──────────────────────────────────────────────────────────────────
    out.info(f"Probing {len(DKIM_SELECTORS)} DKIM selectors ...")
    for sel in DKIM_SELECTORS:
        try:
            answers = resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            for r in answers:
                txt = str(r).strip('"')
                if "v=DKIM1" in txt or "p=" in txt:
                    out.success(f"DKIM selector '{sel}': {txt[:80]}")
                    result["dkim"].append({"selector": sel, "record": txt})
                    # Check key length
                    import re
                    p_match = re.search(r'p=([A-Za-z0-9+/=]+)', txt)
                    if p_match:
                        key_b64 = p_match.group(1)
                        key_len = len(key_b64) * 6 // 8 * 8  # rough bit estimate
                        if key_len < 200:  # ~1024 bit key in base64
                            out.finding("MEDIUM", f"DKIM key for selector '{sel}' may be < 1024 bits — weak",
                                        cwe="CWE-326", module="email_security")
        except Exception:
            pass

    if not result["dkim"]:
        out.finding("MEDIUM", "No DKIM selectors found — DKIM may not be deployed",
                    cwe="CWE-290", module="email_security")
        result["issues"].append({"type": "DKIM", "severity": "MEDIUM", "cwe": "CWE-290",
                                 "desc": "DKIM not detected"})

    # ── BIMI ──────────────────────────────────────────────────────────────────
    try:
        answers = resolver.resolve(f"default._bimi.{domain}", "TXT")
        for r in answers:
            txt = str(r).strip('"')
            out.kv("BIMI", txt[:80])
            result["bimi"] = txt
    except Exception:
        out.info("BIMI record not found (optional)")

    # ── MTA-STS ───────────────────────────────────────────────────────────────
    try:
        answers = resolver.resolve(f"_mta-sts.{domain}", "TXT")
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith("v=STSv1"):
                out.success(f"MTA-STS: {txt}")
                result["mta_sts"] = txt
    except Exception:
        out.info("MTA-STS not configured (optional SMTP hardening)")

    return result
