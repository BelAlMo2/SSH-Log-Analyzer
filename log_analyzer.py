import re

def extract_suspicious_ips(log_file_path, output_file_path):
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
                        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
                            
        # Sort IPs by number of attempts (Descending)
        sorted_ips = sorted(failed_attempts.items(), key=lambda item: item[1], reverse=True)
        
        # Output to screen and write to file
        with open(output_file_path, 'w') as out_file:
            header = "IP Address\t\tAttempts\n" + ("-" * 35) + "\n"
            print(header.strip())
            out_file.write(header)
            
            for ip, count in sorted_ips:
                record = f"{ip}\t\t{count}\n"
                print(record.strip())
                out_file.write(record)
                
        print(f"\n[+] Results successfully saved to: {output_file_path}")
            
    except FileNotFoundError:
        print("[-] Error: Log file not found. Please provide a valid path.")

if __name__ == "__main__":
    # Example usage:
    extract_suspicious_ips("auth.log", "suspicious_ips.txt")
