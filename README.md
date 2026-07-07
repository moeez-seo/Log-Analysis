# Basic Log Analysis Project

## Overview
This is a **Python CLI project** designed as a **defensive cybersecurity and blue-team tool**. It reads standard text-based log files (such as system logs, authentication logs, or web server logs) and generates a security-focused analysis report.

It parses logs to extract IP addresses and timestamps, counts errors and warnings, and detects suspicious activity such as repeated failed logins (brute-force indicators) and highly active IPs.

## Features
* **Modular Structure**: Cleanly separated into configuration, parsing, analyzing, reporting, and CLI logic.
* **Regex-based Parsing**: Extracts IPv4 addresses and standard timestamps from any generic log line.
* **Suspicious Activity Detection**: Identifies IPs that trigger multiple "failed login" events or generate an unusually high volume of traffic.
* **Markdown Export**: Generates a clean, readable Markdown report (`log_analysis_report.md`) for documentation or incident response.

## Requirements
* Python 3.x
* No external dependencies (uses standard library only)

## Usage
1. Open a terminal/command prompt.
2. Navigate to the project directory.
3. Run the application:
   ```bash
   python app.py
   ```
4. From the interactive menu, select **1** and provide the path to a log file (a `sample.log` is provided in this directory for testing).

## Disclaimer
This tool is strictly for educational, defensive, and log analysis purposes. It does not perform active network scanning, exploitation, or any offensive operations.
