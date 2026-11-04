"""Conservative normalization of account-enumeration reports."""
def flag(value):
    return value is True or isinstance(value, str) and value.lower() == "true"


def rows_in(value):
    if isinstance(value, list):
        for row in value:
            yield from rows_in(row)
    elif isinstance(value, dict):
        if "available" in value or "exists" in value or "status" in value or "platform" in value and "success" in value:
            yield value
        else:
            for row in value.values():
                yield from rows_in(row)


def normalize(tool, reports):
    rows = []
    for item in rows_in(reports):
        row = dict(item)
        if tool == "socialscan":
            # The upstream CLI serializes booleans as strings.
            success, valid = flag(row.get("success")), flag(row.get("valid"))
            available = row.get("available")
            known = available is False or flag(available) or isinstance(available, str) and available.lower() == "false"
            row["status"] = "taken" if success and valid and known and not flag(available) else "available" if success and valid and flag(available) else "invalid" if success and not valid else "unknown"
        rows.append(row)
    findings = [r for r in rows if (r.get("status") in {"taken", "found"} or tool == "ignorant" and r.get("exists") is True) and not r.get("error") and not flag(r.get("rateLimit"))]
    problems = [r for r in rows if r.get("status") in {"unknown", "error", "blocked", "timeout"} or r.get("error") or flag(r.get("rateLimit"))]
    return findings, problems, rows
