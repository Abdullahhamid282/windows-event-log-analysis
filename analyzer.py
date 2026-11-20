import csv
from collections import Counter

log_file = "sample_events.csv"
report_file = "results.csv"

events = []

# Read Windows event data
with open(log_file, "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        events.append(row)

# Count failed logins by IP
failed_logins = [
    event for event in events
    if event["Event_ID"] == "4625"
]

ip_counts = Counter(
    event["Source_IP"] for event in failed_logins
)

# Identify successful logins after repeated failures
sequence_alerts = {}

for i, event in enumerate(events):

    if event["Event_ID"] == "4624":

        previous_events = events[:i]

        same_source_failures = [
            previous_event
            for previous_event in previous_events
            if previous_event["Event_ID"] == "4625"
            and previous_event["Source_IP"] == event["Source_IP"]
            and previous_event["Username"] == event["Username"]
        ]

        if len(same_source_failures) >= 5:
            sequence_alerts[event["Source_IP"]] = {
                "username": event["Username"],
                "failed_attempts": len(same_source_failures),
                "success_time": event["Timestamp"]
            }

# Display analysis
print("=== Windows Authentication Analysis ===")

for ip, count in ip_counts.items():

    if count >= 5:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    print(f"\nSource IP: {ip}")
    print(f"Failed attempts: {count}")
    print(f"Status: {status}")

    if status == "SUSPICIOUS":
        print("ALERT: Multiple failed logons detected!")

# Display sequence alerts
print("\n=== Authentication Sequence Analysis ===")

for ip, alert in sequence_alerts.items():

    print("\nALERT: Successful login after repeated failures")
    print(f"Username: {alert['username']}")
    print(f"Source IP: {ip}")
    print(f"Previous failed attempts: {alert['failed_attempts']}")
    print(f"Successful login time: {alert['success_time']}")

# Create investigation report
with open(report_file, "w", newline="") as file:

    writer = csv.writer(file)

    writer.writerow([
        "Source IP",
        "Username",
        "Failed Attempts",
        "Successful Login After Failures",
        "Status"
    ])

    for ip, count in ip_counts.items():

        if ip in sequence_alerts:
            username = sequence_alerts[ip]["username"]
            successful_login = "Yes"
            status = "SUSPICIOUS"
        else:
            username = ""
            successful_login = "No"

            if count >= 5:
                status = "SUSPICIOUS"
            else:
                status = "NORMAL"

        writer.writerow([
            ip,
            username,
            count,
            successful_login,
            status
        ])

print(f"\nInvestigation report saved as {report_file}")