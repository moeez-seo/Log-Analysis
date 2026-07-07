# parser.py
import os
from config import IP_REGEX, TIMESTAMP_REGEX, KEYWORDS_FAILED_LOGIN, KEYWORDS_ERROR, KEYWORDS_WARNING

def extract_ip(line: str) -> str:
    match = IP_REGEX.search(line)
    return match.group(0) if match else None

def extract_timestamp(line: str) -> str:
    match = TIMESTAMP_REGEX.search(line)
    return match.group(0) if match else "Unknown Time"

def categorize_event(line: str) -> str:
    lower_line = line.lower()
    
    for kw in KEYWORDS_FAILED_LOGIN:
        if kw in lower_line:
            return "FAILED_LOGIN"
            
    for kw in KEYWORDS_ERROR:
        if kw in lower_line:
            return "ERROR"
            
    for kw in KEYWORDS_WARNING:
        if kw in lower_line:
            return "WARNING"
            
    return "INFO"

def parse_log_file(filepath: str) -> list:
    """
    Reads a log file line by line and extracts relevant entities.
    Returns a list of dictionaries representing each parsed line.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
        
    parsed_events = []
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
                
            event = {
                "line_number": idx + 1,
                "raw": line,
                "timestamp": extract_timestamp(line),
                "ip": extract_ip(line),
                "category": categorize_event(line)
            }
            parsed_events.append(event)
            
    return parsed_events
