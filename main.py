from detector import detect_suspicious_logins
import datetime

LOG_FILE = "test_auth.log"           # or "/var/log/auth.log"
ALERT_OUTPUT = "alerts.log"          # file to save alerts

def log_alerts_to_file(detections, output_file):
    with open(output_file, "a") as f:
        f.write(f"\n===== Run at {datetime.datetime.now()} =====\n")
        for alert in detections:
            if alert['type'] == "fail_burst":
                f.write(f"""[FAIL BURST] User: {alert['user']}
Failed Attempts: {alert['fail_count']} within time window
Failed IPs: {', '.join(alert['fail_ips'])}
Time: {alert['time']}
---
""")
            elif alert['type'] == "success_after_fail":
                f.write(f"""[SUCCESS AFTER FAIL] User: {alert['user']}
Successful Login From: {alert['success_ip']} at {alert['success_time']}
Failed Attempts Before Success: {alert['fail_count']}
Failed IPs: {', '.join(alert['fail_ips'])}
---
""")

if __name__ == "__main__":
    detections = detect_suspicious_logins(LOG_FILE)

    if detections:
        print("🚨 Suspicious login activity detected:")
        for alert in detections:
            if alert['type'] == "fail_burst":
                print(f"""
[FAIL BURST] User: {alert['user']}
Failed Attempts: {alert['fail_count']} within time window
Failed IPs: {', '.join(alert['fail_ips'])}
Time: {alert['time']}
""")
            elif alert['type'] == "success_after_fail":
                print(f"""
[SUCCESS AFTER FAIL] User: {alert['user']}
Successful Login From: {alert['success_ip']} at {alert['success_time']}
Failed Attempts Before Success: {alert['fail_count']}
Failed IPs: {', '.join(alert['fail_ips'])}
""")
        log_alerts_to_file(detections, ALERT_OUTPUT)
        print(f"💾 Alerts saved to {ALERT_OUTPUT}")
    else:
        print("✅ No suspicious login patterns detected.")
