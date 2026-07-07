# analyzer.py
from collections import Counter
from config import FAILED_LOGIN_THRESHOLD, SUSPICIOUS_IP_THRESHOLD

def analyze_logs(parsed_events: list) -> dict:
    """
    Analyzes the parsed log events to generate counts, top IPs, and identify suspicious activity.
    """
    summary = {
        "total_lines": len(parsed_events),
        "counts": {
            "INFO": 0,
            "WARNING": 0,
            "ERROR": 0,
            "FAILED_LOGIN": 0
        },
        "top_ips": [],
        "suspicious_activity": []
    }
    
    ip_counter = Counter()
    failed_login_ips = Counter()
    
    for event in parsed_events:
        cat = event["category"]
        if cat in summary["counts"]:
            summary["counts"][cat] += 1
            
        ip = event["ip"]
        if ip:
            ip_counter[ip] += 1
            if cat == "FAILED_LOGIN":
                failed_login_ips[ip] += 1
                
    # Get top 5 active IPs
    summary["top_ips"] = ip_counter.most_common(5)
    
    # Detect Suspicious Activity (Brute Force Indicators)
    for ip, count in failed_login_ips.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            summary["suspicious_activity"].append(
                f"🚨 Brute-force indicator: IP {ip} had {count} failed login attempts."
            )
            
    # Detect highly active IPs (Possible DoS/Scraping)
    for ip, count in ip_counter.items():
        if count >= SUSPICIOUS_IP_THRESHOLD:
            # We don't want to double alert if it's already a brute force alert
            if failed_login_ips[ip] < FAILED_LOGIN_THRESHOLD:
                summary["suspicious_activity"].append(
                    f"⚠️ High activity indicator: IP {ip} generated {count} total log events."
                )
                
    return summary
