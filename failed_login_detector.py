"""
Python Failed Login Detector
Author: Muhib Khan

Purpose:
    Analyze FICTIONAL login records and flag IP addresses whose failed-login
    behavior matches two simple, rule-based patterns:

      Rule 1 - Repeated failed logins:  5 or more failed attempts from one IP.
      Rule 2 - Multiple usernames:      failed attempts against 3 or more
                                        different usernames from one IP.

    This is an educational project. It reads no real logs and monitors no
    live systems. It uses only Python's standard library.
"""

import ipaddress
from pathlib import Path

# ---------------------------------------------------------------------------
# 1. Detection settings (change these to experiment with the rules)
# ---------------------------------------------------------------------------
FAILURE_THRESHOLD = 5    # Rule 1: failed attempts from one IP
USERNAME_THRESHOLD = 3   # Rule 2: unique usernames targeted by one IP

VALID_STATUSES = {"SUCCESS", "FAILED"}
REPORT_FILENAME = "failed_login_security_report.txt"
REPORT_WIDTH = 60

# ---------------------------------------------------------------------------
# 2. Fictional sample data
#    IP addresses come from the ranges reserved for documentation
#    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so they are not
#    real hosts. The last four entries are deliberately malformed.
# ---------------------------------------------------------------------------
SAMPLE_LOGIN_LOGS = [
    # Normal activity
    {"ip": "192.0.2.10", "username": "alice", "status": "SUCCESS"},
    {"ip": "192.0.2.11", "username": "bob", "status": "SUCCESS"},
    {"ip": "198.51.100.14", "username": "guest", "status": "FAILED"},
    {"ip": "198.51.100.14", "username": "guest", "status": "SUCCESS"},

    # Exactly 5 failures against ONE username -> Rule 1 only
    {"ip": "203.0.113.25", "username": "admin", "status": "FAILED"},
    {"ip": "203.0.113.25", "username": "admin", "status": "FAILED"},
    {"ip": "203.0.113.25", "username": "admin", "status": "FAILED"},
    {"ip": "203.0.113.25", "username": "admin", "status": "FAILED"},
    {"ip": "203.0.113.25", "username": "admin", "status": "FAILED"},

    # 3 failures against 3 DIFFERENT usernames -> Rule 2 only
    {"ip": "198.51.100.77", "username": "admin", "status": "FAILED"},
    {"ip": "198.51.100.77", "username": "root", "status": "FAILED"},
    {"ip": "198.51.100.77", "username": "guest", "status": "FAILED"},

    # 6 failures against 4 usernames -> Rule 1 AND Rule 2
    {"ip": "203.0.113.200", "username": "admin", "status": "FAILED"},
    {"ip": "203.0.113.200", "username": "root", "status": "FAILED"},
    {"ip": "203.0.113.200", "username": "test", "status": "FAILED"},
    {"ip": "203.0.113.200", "username": "oracle", "status": "FAILED"},
    {"ip": "203.0.113.200", "username": "admin", "status": "FAILED"},
    {"ip": "203.0.113.200", "username": "root", "status": "FAILED"},

    # 4 failures, 1 username -> just under both thresholds, NOT flagged
    {"ip": "203.0.113.90", "username": "bob", "status": "FAILED"},
    {"ip": "203.0.113.90", "username": "bob", "status": "FAILED"},
    {"ip": "203.0.113.90", "username": "bob", "status": "FAILED"},
    {"ip": "203.0.113.90", "username": "bob", "status": "FAILED"},

    # 2 failures, 2 usernames (lowercase/padded status is normalized)
    {"ip": "192.0.2.50", "username": "alice", "status": "failed"},
    {"ip": "192.0.2.50", "username": "carol", "status": " FAILED "},

    # Malformed records (these should be skipped and reported)
    {"ip": "203.0.113.5", "status": "FAILED"},                       # missing username
    {"ip": "999.1.1.1", "username": "admin", "status": "FAILED"},    # invalid IP
    {"ip": "203.0.113.6", "username": "admin", "status": "MAYBE"},   # unknown status
    "this is not a record",                                          # not a dictionary
]


# ---------------------------------------------------------------------------
# 3. Validation: decide whether a single record is usable
# ---------------------------------------------------------------------------
def validate_record(record):
    """Check one login record.

    Returns (clean_record, None) if the record is valid, or
    (None, reason) if it is malformed. A valid record is returned in a
    normalized form: IP in standard notation, username lowercase,
    status uppercase.
    """
    if not isinstance(record, dict):
        return None, "record is not a dictionary"

    for field in ("ip", "username", "status"):
        if field not in record:
            return None, f"missing field '{field}'"
        if not isinstance(record[field], str) or not record[field].strip():
            return None, f"field '{field}' is empty or not text"

    try:
        # ip_address() rejects values like "999.1.1.1" or "abc".
        ip = str(ipaddress.ip_address(record["ip"].strip()))
    except ValueError:
        return None, f"invalid IP address '{record['ip']}'"

    status = record["status"].strip().upper()
    if status not in VALID_STATUSES:
        return None, f"unknown status '{record['status']}'"

    username = record["username"].strip().lower()
    return {"ip": ip, "username": username, "status": status}, None


# ---------------------------------------------------------------------------
# 4. Analysis: count failures and apply the detection rules
# ---------------------------------------------------------------------------
def analyze_logins(records, failure_threshold=FAILURE_THRESHOLD,
                   username_threshold=USERNAME_THRESHOLD):
    """Analyze login records and return a dictionary of results.

    Empty input (None, an empty list, or something that is not a list/tuple)
    is handled safely and produces a result with all counts at zero.
    """
    if not isinstance(records, (list, tuple)):
        records = []  # treat unusable input as "no records"

    results = {
        "total_records": len(records),
        "valid_records": 0,
        "successful_logins": 0,
        "failed_attempts": 0,
        "malformed": [],        # list of (record number, reason)
        "failures_by_ip": {},   # ip -> number of failed attempts
        "usernames_by_ip": {},  # ip -> set of usernames that failed
        "flagged": {},          # ip -> details for IPs that broke a rule
        "failure_threshold": failure_threshold,
        "username_threshold": username_threshold,
    }

    for number, record in enumerate(records, start=1):
        clean, reason = validate_record(record)
        if clean is None:
            results["malformed"].append((number, reason))
            continue

        results["valid_records"] += 1

        if clean["status"] == "SUCCESS":
            results["successful_logins"] += 1
            continue

        # Only FAILED records reach this point.
        ip = clean["ip"]
        results["failed_attempts"] += 1
        results["failures_by_ip"][ip] = results["failures_by_ip"].get(ip, 0) + 1
        results["usernames_by_ip"].setdefault(ip, set()).add(clean["username"])

    # Apply the detection rules to each IP that had at least one failure.
    for ip, count in results["failures_by_ip"].items():
        usernames = results["usernames_by_ip"][ip]
        reasons = []

        if count >= failure_threshold:
            reasons.append("Repeated failed logins")
        if len(usernames) >= username_threshold:
            reasons.append("Multiple usernames targeted")

        if reasons:
            results["flagged"][ip] = {
                "failed_attempts": count,
                "usernames": sorted(usernames),
                "reasons": reasons,
            }

    return results


# ---------------------------------------------------------------------------
# 5. Reporting: turn the results into readable text
# ---------------------------------------------------------------------------
def _ip_sort_key(ip):
    """Sort IP addresses numerically instead of alphabetically."""
    address = ipaddress.ip_address(ip)
    return (address.version, int(address))


def build_report(results):
    """Return the full security report as a single string."""
    line = "=" * REPORT_WIDTH
    dash = "-" * REPORT_WIDTH
    failure_threshold = results["failure_threshold"]
    username_threshold = results["username_threshold"]

    lines = [
        line,
        "FAILED LOGIN DETECTION REPORT",
        line,
        "",
        "SUMMARY",
        dash,
        f"Total login records:       {results['total_records']}",
        f"Valid records analyzed:    {results['valid_records']}",
        f"Malformed records skipped: {len(results['malformed'])}",
        f"Successful logins:         {results['successful_logins']}",
        f"Total failed attempts:     {results['failed_attempts']}",
        f"IPs with failed attempts:  {len(results['failures_by_ip'])}",
        f"Total IPs flagged:         {len(results['flagged'])}",
        "",
        "DETECTION RULES",
        dash,
        f"Rule 1 - Repeated failed logins: {failure_threshold} or more "
        "failed attempts from one IP.",
        f"Rule 2 - Multiple usernames: failed attempts against "
        f"{username_threshold} or more",
        "         different usernames from one IP.",
        "",
        "FLAGGED IP ADDRESSES",
        dash,
    ]

    if results["flagged"]:
        for ip in sorted(results["flagged"], key=_ip_sort_key):
            info = results["flagged"][ip]
            lines.append(f"WARNING: {ip}")
            lines.append(f"  Failed attempts:  {info['failed_attempts']}")
            lines.append(f"  Unique usernames: {len(info['usernames'])} "
                         f"({', '.join(info['usernames'])})")
            lines.append(f"  Reason(s):        {'; '.join(info['reasons'])}")
            lines.append("")
    else:
        lines.append("No IP addresses triggered an alert.")
        lines.append("")

    lines.append("IPs WITH FAILED ATTEMPTS BUT NOT FLAGGED")
    lines.append(dash)
    not_flagged = [ip for ip in results["failures_by_ip"]
                   if ip not in results["flagged"]]
    if not_flagged:
        for ip in sorted(not_flagged, key=_ip_sort_key):
            count = results["failures_by_ip"][ip]
            names = len(results["usernames_by_ip"][ip])
            lines.append(f"{ip}: {count} failed attempt(s), "
                         f"{names} unique username(s)")
    else:
        lines.append("None.")
    lines.append("")

    lines.append("MALFORMED RECORDS SKIPPED")
    lines.append(dash)
    if results["malformed"]:
        for number, reason in results["malformed"]:
            lines.append(f"Record #{number}: {reason}")
    else:
        lines.append("None.")
    lines.append("")

    lines.extend([
        "LIMITATIONS",
        dash,
        "- Uses fictional sample records only; it does not read real logs.",
        "- Does not monitor live systems or detect real attackers.",
        "- Has no time window, so failures spread over days count together.",
        "- Fixed thresholds can cause false positives and false negatives.",
        "- Does not use IP reputation, geolocation, or account lockout data.",
        "- An alert is a lead for review, not proof of malicious activity.",
        "",
        "Data source: Fictional practice records.",
        "For educational use only.",
        line,
    ])

    return "\n".join(lines)


def save_report(report_text, filename=REPORT_FILENAME):
    """Save the report next to this script and return the file path."""
    path = Path(__file__).resolve().parent / filename
    path.write_text(report_text + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 6. Main program
# ---------------------------------------------------------------------------
def main():
    results = analyze_logins(SAMPLE_LOGIN_LOGS)
    report = build_report(results)
    print(report)
    path = save_report(report)
    print(f"\nSecurity report saved to: {path.name}")


if __name__ == "__main__":
    main()
