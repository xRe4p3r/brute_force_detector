import re
import datetime
from collections import defaultdict

FAIL_REGEX = re.compile(
    r'^(\w{3}\s+\d+\s[\d:]+)\s[\w\W]+sshd[\[\]\d]*: Failed password for(?: invalid user)? (\w+) from (\d+\.\d+\.\d+\.\d+)'
)

SUCCESS_REGEX = re.compile(
    r'^(\w{3}\s+\d+\s[\d:]+)\s[\w\W]+sshd[\[\]\d]*: Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)'
)

def parse_syslog_time(timestr):
    current_year = datetime.datetime.now().year
    return datetime.datetime.strptime(f"{timestr} {current_year}", "%b %d %H:%M:%S %Y")

def detect_suspicious_logins(log_file, fail_threshold=5, time_window=60):
    failed_logins = defaultdict(list)  # user -> list of (time, ip)
    alerts = []
    alerted_fail_indices = defaultdict(set)  # user -> set of indices already alerted on

    with open(log_file, "r") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        fail_match = FAIL_REGEX.match(line)
        if fail_match:
            timestamp, user, ip = fail_match.groups()
            t = parse_syslog_time(timestamp)
            failed_logins[user].append((t, ip))

            # Check for failed bursts (≥ fail_threshold fails in time_window)
            fails = failed_logins[user]
            recent_fails = [
                (idx, ft, fip) for idx, (ft, fip) in enumerate(fails)
                if t - datetime.timedelta(seconds=time_window) <= ft <= t
            ]

            # Filter those not alerted yet
            new_fails = [item for item in recent_fails if item[0] not in alerted_fail_indices[user]]

            if len(new_fails) >= fail_threshold:
                for idx, _, _ in new_fails:
                    alerted_fail_indices[user].add(idx)

                alerts.append({
                    "type": "fail_burst",
                    "user": user,
                    "fail_count": len(new_fails),
                    "fail_ips": list(set(ip for _, ip in [(ft, fip) for _, ft, fip in new_fails])),
                    "time": t
                })

            continue

        success_match = SUCCESS_REGEX.match(line)
        if success_match:
            timestamp, user, ip = success_match.groups()
            t = parse_syslog_time(timestamp)

            fails = failed_logins[user]
            recent_fails = [
                (ft, fip) for ft, fip in fails
                if t - datetime.timedelta(seconds=time_window) <= ft < t
            ]

            if len(recent_fails) >= fail_threshold:
                alerts.append({
                    "type": "success_after_fail",
                    "user": user,
                    "success_ip": ip,
                    "success_time": t,
                    "fail_count": len(recent_fails),
                    "fail_ips": list(set(ip for _, ip in recent_fails))
                })

    return alerts

