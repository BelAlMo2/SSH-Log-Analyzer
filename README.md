#  SSH Log Analyzer (Brute-Force Detector)

A Python script designed for SOC Analysts to quickly parse Linux `auth.log` files, extract suspicious IP addresses attempting SSH brute-force attacks, and export the results for firewall blocking.

###  Features
* **Regex-based Parsing:** Accurately extracts IPv4 addresses.
* **Frequency Analysis:** Counts and sorts failed login attempts descendingly.
* **Automated Reporting:** Outputs a clear table to the console and exports a `suspicious_ips.txt` file for SIEM/Firewall integration.

###  Usage
Simply run the script in the same directory as your log file:
`python log_analyzer.py`
