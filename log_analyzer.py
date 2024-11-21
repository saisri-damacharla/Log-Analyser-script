import re
from collections import Counter

def parse_logs(file_path):
    """
    Parses the log file and extracts relevant information.

    :param file_path: Path to the log file
    :return: List of log entries and detected suspicious IPs
    """
    log_entries = []
    ip_addresses = []

    with open(file_path, 'r') as file:
        for line in file:
            # Example log format: [Date] [Severity] [IP] [Message]
            match = re.match(r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)', line)
            if match:
                date, severity, ip, message = match.groups()
                log_entries.append({'date': date, 'severity': severity, 'ip': ip, 'message': message})
                ip_addresses.append(ip)

    # Count occurrences of each IP
    ip_count = Counter(ip_addresses)
    suspicious_ips = [ip for ip, count in ip_count.items() if count > 5]

    return log_entries, suspicious_ips


def filter_by_severity(log_entries, severity_level):
    """
    Filters log entries by severity level.

    :param log_entries: List of log entries
    :param severity_level: Severity level to filter (e.g., ERROR, WARNING)
    :return: Filtered log entries
    """
    return [entry for entry in log_entries if entry['severity'] == severity_level]


def main():
    log_file = 'server.log'
    logs, suspicious_ips = parse_logs(log_file)

    print("\n--- Filtered Logs by Severity: ERROR ---")
    error_logs = filter_by_severity(logs, 'ERROR')
    for log in error_logs:
        print(log)

    print("\n--- Suspicious IPs (More than 5 Hits) ---")
    for ip in suspicious_ips:
        print(ip)


if __name__ == '__main__':
    main()

