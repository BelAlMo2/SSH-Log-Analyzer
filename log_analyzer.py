import re

def extract_suspicious_ips(log_file_path):
    print(f"[*] Analyzing {log_file_path} for brute-force attacks...\n")
    failed_attempts = {}
    
    # Regex pattern to match IP addresses
    ip_pattern = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
    
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                # Looking for failed login indicators in Linux auth.log
                if "Failed password" in line:
                    ips = ip_pattern.findall(line)
                    for ip in ips:
                        if ip in failed_attempts:
                            failed_attempts[ip] += 1
                        else:
                            failed_attempts[ip] = 1
                            
        print("[+] Suspicious IPs Found:")
        print("-" * 35)
        print("IP Address\t\tAttempts")
        print("-" * 35)
        
        # Sort IPs by number of attempts (Descending)
        sorted_ips = sorted(failed_attempts.items(), key=lambda item: item[1], reverse=True)
        
        for ip, count in sorted_ips:
            print(f"{ip}\t\t{count}")
            
    except FileNotFoundError:
        print("[-] Error: Log file not found. Please provide a valid path.")

if __name__ == "__main__":
    # Example usage: Replace 'auth.log' with the actual log file path
    extract_suspicious_ips("auth.log")
