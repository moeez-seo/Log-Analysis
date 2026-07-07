# config.py
import re

OUTPUT_FILENAME = "log_analysis_report.md"

# Thresholds for triggering suspicious activity alerts
FAILED_LOGIN_THRESHOLD = 5
SUSPICIOUS_IP_THRESHOLD = 10

# Regular expressions
IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
TIMESTAMP_REGEX = re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{2}:\d{2}:\d{2}\b|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')

# Keywords for categorization (lowercased for case-insensitive matching)
KEYWORDS_FAILED_LOGIN = ["failed password", "login failed", "authentication failure", "invalid user"]
KEYWORDS_ERROR = ["error", "fatal", "critical", "exception", "traceback"]
KEYWORDS_WARNING = ["warning", "warn", "timeout"]
