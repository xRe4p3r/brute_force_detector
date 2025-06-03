# 🛡️ Brute Force SSH Detector

This is a simple tool built in Python that detects brute force SSH login attempts by monitoring log files. It's designed to alert you when:

- There are 5 or more failed login attempts in a short period.
- A successful login happens shortly after repeated failures — which may indicate a successful brute force attack.

## 🛠 What It Does

- Scans SSH login logs (like `/var/log/auth.log`)
- Detects multiple failed login attempts from any IP address
- Detects successful login following failed attempts
- Alerts are saved to a file (`alerts.log`) and printed to the screen

## 📁 Project Structure

brute-force-ssh-detector/
- detector.py # Core logic for parsing and detection
- main.py # Entry point to run the tool
- test_auth.log # Sample log file for testing
- alerts.log # Output file with suspicious activity logs


## 🚀 How to Use It

1. Clone the repository or download the files.
2. (Optional) Replace `test_auth.log` with your real SSH log (e.g., `/var/log/auth.log`)
3. Run the tool:
   ```bash
   python3 main.py


## 🧪 Sample Output (alerts.log)

[ALERT] 5+ failed login attempts for user 'admin' between 15:00:01 and 15:00:40
[ALERT] Successful login for user 'admin' from IP 11.11.11.11 after multiple failures

## 📌 Notes

The detection threshold is set to 5 failed attempts in 60 seconds.
Adjust the LOG_FILE path in main.py if you're using a different log file.
