import argparse
import os
import re
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta

import csv
import json


BURST_LIMIT = 8
BURST_TIME = 60

PERSISTENT_LIMIT = 10
PERSISTENT_TIME = 15 * 60

MANY_USERS_LIMIT = 5
INVALID_USER_LIMIT = 2

# REGEX PATTERNS

login_pattern = (
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) "
    r"\S+ "
    r"sshd\[(?P<pid>\d+)\]: "
    r"(?P<status>Accepted|Failed) "
    r"(?:password|publickey) for "
    r"(?:(?P<invalid>invalid user) )?"
    r"(?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) "
    r"port (?P<port>\d+)"
)


session_pattern = (
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) "
    r"\S+ "
    r"sshd\[(?P<pid>\d+)\]: "
    r"pam_unix\(sshd:session\): "
    r"session (?P<event>opened|closed) for user (?P<user>[\w.\-]+)"
)


sudo_pattern = (
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) "
    r"\S+ "
    r"sudo:\s+"
    r"(?P<user>\S+) : "
    r".*?USER=(?P<target_user>\S+) ; "
    r"COMMAND=(?P<command>.+)$"
)

# TIMESTAMP
def parse_timestamp(timestamp):
    # Syslog timestamps have no year. strptime without a year defaults to
    # 1900 (not a leap year) and crashes on "Feb 29". Use a fixed leap year.
    return datetime.strptime(
        "2000 " + timestamp,
        "%Y %b %d %H:%M:%S"
    )
# PARSE ONE LINE
def _match_line(line):

    # -------- SSH LOGIN --------

    login_match = re.search(login_pattern,line)
    
    if login_match:

        if login_match.group("status") == "Accepted":
            status = "success"
        else:
            status = "failure"

        event = {
            "timestamp": login_match.group("timestamp"),
            "ip": login_match.group("ip"),
            "user": login_match.group("user"),
            "event_type": "ssh_login",
            "status": status,
            "pid": login_match.group("pid"),
            "port": login_match.group("port"),
            "invalid_user": login_match.group("invalid") is not None
        }

        return event


    # -------- SESSION --------

    session_match = re.search(
        session_pattern,
        line
    )

    if session_match:

        if session_match.group("event") == "opened":
            event_type = "session_open"
        else:
            event_type = "session_close"

        event = {
            "timestamp": session_match.group("timestamp"),
            "ip": None,
            "user": session_match.group("user"),
            "event_type": event_type,
            "status": None,
            "pid": session_match.group("pid"),
            "port": None
        }

        return event


    # -------- SUDO --------

    sudo_match = re.search(
        sudo_pattern,
        line
    )

    if sudo_match:

        event = {
            "timestamp": sudo_match.group("timestamp"),
            "ip": None,
            "user": sudo_match.group("user"),
            "event_type": "sudo_command",
            "status": None,
            "pid": None,
            "port": None,
            "target_user": sudo_match.group("target_user"),
            "command": sudo_match.group("command")
        }

        return event
        
    # Unknown / malformed line

    return None


def parse_line(line):

    event = _match_line(line)

    if event is None:
        return None

    # Reject lines whose timestamp looks valid to the regex but is not a
    # real date/time (e.g. "Oct 99 99:99:99"). Prevents crashes later.
    try:
        parse_timestamp(event["timestamp"])
    except ValueError:
        return None

    return event

# SECURITY THREAT DETECTION


def detect_security_threats(login_events):
    # Get only failed login attempts

    failed_events = [
        event
        for event in login_events
        if event["status"] == "failure"]


    # Group all login events by IP

    events_by_ip = {}

    for event in login_events:

        ip = event["ip"]

        if ip not in events_by_ip:
            events_by_ip[ip] = []

        events_by_ip[ip].append(event)


    # Group failed events by IP

    failed_by_ip = defaultdict(list)

    for event in failed_events:

        failed_by_ip[event["ip"]].append(event)


    # Sort events by timestamp

    for ip in events_by_ip:

        events_by_ip[ip].sort(
            key=lambda event: parse_timestamp(
                event["timestamp"])
        )

    for ip in failed_by_ip:

        failed_by_ip[ip].sort(
            key=lambda event: parse_timestamp(
                event["timestamp"]
            )
        )


    security_results = {}


    # Check every IP

    for ip in events_by_ip:

        score = 0
        reasons = []

        ip_failed = failed_by_ip.get(
            ip,
            []
        )

        # RULE 1: BURST FAILURES
        
        burst_detected = False

        for i in range(len(ip_failed)):

            start_time = parse_timestamp(
                ip_failed[i]["timestamp"]
            )

            count = 1

            for j in range(i + 1, len(ip_failed)):

                current_time = parse_timestamp(
                    ip_failed[j]["timestamp"]
                )

                difference = (
                    current_time - start_time
                ).total_seconds()

                if difference <= BURST_TIME:
                    count += 1
                else:
                    break

            if count >= BURST_LIMIT:
                burst_detected = True
                break


        if burst_detected:

            score += 3

            reasons.append(
                f"Burst failures: {BURST_LIMIT}+ failures "
                f"within {BURST_TIME} seconds"
            )
        
        # RULE 2: PERSISTENT FAILURES
        persistent_detected = False

        for i in range(len(ip_failed)):

            start_time = parse_timestamp(
                ip_failed[i]["timestamp"]
            )

            count = 1

            for j in range(i + 1, len(ip_failed)):

                current_time = parse_timestamp(
                    ip_failed[j]["timestamp"]
                )

                difference = (
                    current_time - start_time
                ).total_seconds()

                if difference <= PERSISTENT_TIME:
                    count += 1
                else:
                    break

            if count >= PERSISTENT_LIMIT:
                persistent_detected = True
                break


        if persistent_detected:
            score += 2
            reasons.append(
                f"Persistent failures: {PERSISTENT_LIMIT}+ "
                f"failures within 15 minutes"
            )
        # RULE 3: MANY USERNAME
        usernames = set()

        for event in ip_failed:

            if event["user"] is not None:

                usernames.add(
                    event["user"]
                )


        if len(usernames) >= MANY_USERS_LIMIT:

            score += 2

            reasons.append(
                f"Many usernames targeted: "
                f"{len(usernames)} different users"
            )


        # RULE 4: INVALID USERS

        invalid_count = 0

        for event in ip_failed:

            if event["invalid_user"] is True:

                invalid_count += 1


        if invalid_count >= INVALID_USER_LIMIT:

            score += 2

            reasons.append(
                f"Repeated invalid usernames: "
                f"{invalid_count} attempts"
            )
        # SUSPICION LEVEL

        if score >= 5:

            level = "HIGH SUSPICION"

        elif score >= 3:

            level = "SUSPICIOUS"

        else:

            level = "NORMAL"


        # Save result if any rule triggered

        if score > 0:

            security_results[ip] = {
                "score": score,
                "level": level,
                "reasons": reasons
            }


    return security_results

# LIVE SECURITY DETECTION
def build_threat_result(burst, persistent, user_count, invalid_count):
    # Same scoring, reasons and levels as detect_security_threats(),
    # but computed from running counters instead of full event lists.

    score = 0
    reasons = []

    if burst:

        score += 3

        reasons.append(
            f"Burst failures: {BURST_LIMIT}+ failures "
            f"within {BURST_TIME} seconds"
        )

    if persistent:

        score += 2

        reasons.append(
            f"Persistent failures: {PERSISTENT_LIMIT}+ "
            f"failures within 15 minutes"
        )

    if user_count >= MANY_USERS_LIMIT:

        score += 2

        reasons.append(
            f"Many usernames targeted: "
            f"{user_count} different users"
        )

    if invalid_count >= INVALID_USER_LIMIT:

        score += 2

        reasons.append(
            f"Repeated invalid usernames: "
            f"{invalid_count} attempts"
        )

    if score >= 5:
        level = "HIGH SUSPICION"
    elif score >= 3:
        level = "SUSPICIOUS"
    else:
        level = "NORMAL"

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }

# EXPORT (JSON / CSV)

CSV_FIELDS = [
    "timestamp", "ip", "user", "event_type", "status",
    "pid", "port", "invalid_user", "target_user", "command"
]

def export_json(path, events, summary, security_results):

    data = {
        "summary": summary,
        "security_report": security_results,
        "events": events
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def export_csv(path, events, security_results):

    # 1) All parsed events
    with open(path, "w", newline="", encoding="utf-8") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=CSV_FIELDS,
            restval="",
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(events)

    # 2) Security report -> <name>_security.csv
    base, ext = os.path.splitext(path)
    security_path = base + "_security" + (ext or ".csv")

    with open(security_path, "w", newline="", encoding="utf-8") as f:

        writer = csv.writer(f)

        writer.writerow(["ip", "score", "level", "reasons"])

        for ip, result in security_results.items():

            writer.writerow([
                ip,
                result["score"],
                result["level"],
                "; ".join(result["reasons"])
            ])

    return security_path

# COMMAND LINE ARGUMENT

parser = argparse.ArgumentParser(
    description="Parse Linux authentication logs"
)

parser.add_argument(
    "file",
    help="Path to the authentication log file"
)

parser.add_argument(
    "--json",
    metavar="FILE",
    help="Export parsed events, summary and security report to a JSON file"
)

parser.add_argument(
    "--csv",
    metavar="FILE",
    help="Export parsed events to a CSV file (security report goes to FILE_security.csv)"
)

args = parser.parse_args()

# READ LOG FILE


events = []

login_events = []
session_events = []
sudo_events = []


try:

    with open(args.file, "r", encoding="utf-8", errors="replace") as file:

        for line in file:

            line = line.strip()

            event = parse_line(line)

            if event is not None:

                events.append(event)

except FileNotFoundError:

    print(f"Error: File '{args.file}' not found.")
    exit()

except PermissionError:

    print(f"Error: Permission denied for '{args.file}'.")
    exit()


if len(events) == 0:

    print("Error: File is empty or contains no valid log entries.")
    exit()

# SEPARATE EVENT TYPES

for event in events:

    if event["event_type"] == "ssh_login":

        login_events.append(event)

    elif (
        event["event_type"] == "session_open"
        or event["event_type"] == "session_close"
    ):

        session_events.append(event)

    elif event["event_type"] == "sudo_command":

        sudo_events.append(event)
# SUMMARY
total_attempts = len(login_events)

status_counts = Counter(
    event["status"]
    for event in login_events)

username_counts = Counter(
    event["user"]
    for event in login_events
    if event["user"] is not None
)


ip_counts = Counter(
    event["ip"] for event in login_events
    if event["ip"] is not None)



# PRINT PARSED EVENTS


print("\n====== PARSED EVENTS ======")

for event in events:

    print(event)



# PRINT SUMMARY


print("\n======== SUMMARY ========")

print("Total events:",len(events))

print("Total login attempts:",total_attempts)

print("Successful logins:",status_counts["success"])

print("Failed logins:",status_counts["failure"])

print("Session events:",len(session_events))

print("Sudo commands:",len(sudo_events))


print("\nTop targeted usernames:")

for user, count in username_counts.most_common(5):

    print(user,":",count)


print("\nTop originating source IPs:")

for ip, count in ip_counts.most_common(5):

    print(ip,":",count)

# SECURITY REPORT

security_results = detect_security_threats(login_events)


print("\n====== SECURITY REPORT ======")


if len(security_results) == 0:

    print("No suspicious activity detected.")

else:

    for ip, result in security_results.items():

        print("\nIP:", ip)

        print("Score:",result["score"])

        print("Level:",result["level"])

        print("Reasons:")

        for reason in result["reasons"]:

            print("-",reason)

# EXPORT FILES


summary = {
    "total_events": len(events),
    "total_login_attempts": total_attempts,
    "successful_logins": status_counts["success"],
    "failed_logins": status_counts["failure"],
    "session_events": len(session_events),
    "sudo_commands": len(sudo_events),
    "top_usernames": dict(username_counts.most_common(5)),
    "top_ips": dict(ip_counts.most_common(5))
}

try:

    if args.json:
        export_json(args.json, events, summary, security_results)
        print(f"\nJSON exported to: {args.json}")

    if args.csv:
        security_csv = export_csv(args.csv, events, security_results)
        print(f"CSV exported to: {args.csv}")
        print(f"Security CSV exported to: {security_csv}")

except (PermissionError, OSError) as error:

    print(f"Error: Could not write export file: {error}")
    
