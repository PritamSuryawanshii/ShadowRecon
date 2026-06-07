"""shadowrecon/modules/mod_whois.py"""

from datetime import datetime, timezone


def run(domain, args, out, state):
    result = {}
    try:
        import whois as pywhois
        w = pywhois.whois(domain)
    except Exception as e:
        out.fail(f"WHOIS failed: {e}")
        return result

    fields = {
        "Registrar":        getattr(w, "registrar", None),
        "Registrant Org":   getattr(w, "org", None),
        "Registrant Email": getattr(w, "emails", None),
        "Created":          getattr(w, "creation_date", None),
        "Expires":          getattr(w, "expiration_date", None),
        "Updated":          getattr(w, "updated_date", None),
        "Name Servers":     getattr(w, "name_servers", None),
        "Status":           getattr(w, "status", None),
        "Country":          getattr(w, "country", None),
    }
    for k, v in fields.items():
        if v:
            if isinstance(v, list):
                v = v[0] if len(v) == 1 else str(v[:4])
            out.kv(k, str(v))
            result[k] = str(v)

    # Expiry alert
    exp = getattr(w, "expiration_date", None)
    if exp:
        exp = exp[0] if isinstance(exp, list) else exp
        try:
            if hasattr(exp, "replace"):
                exp = exp.replace(tzinfo=timezone.utc) if exp.tzinfo is None else exp
            days = (exp - datetime.now(timezone.utc)).days
            if days < 30:
                out.finding("HIGH", f"Domain expires in {days} days — renewal/hijack risk",
                            cwe="CWE-284", module="whois")
                result["expiry_alert"] = days
            else:
                out.info(f"Domain expires in {days} days")
        except Exception:
            pass

    return result
