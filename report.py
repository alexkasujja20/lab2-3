#!/usr/bin/env python3
"""
lab2_3_detector.py

Full working script:
- Parses sample_auth_small.log (assumes same format as lab)
- Builds per-ip failed-attempt timestamp lists
- Detects brute-force bursts (>= threshold attempts within max_minutes)
- Writes incidents to bruteforce_incidents.txt (pretty JSON)
- Prints summary and optionally plots top attackers if matplotlib available
"""

import json
from collections import defaultdict
from datetime import datetime, timedelta
import sys
LOGFILE = "sample_auth_small.log"


def parse_auth_line(line):
    """
    Parse an auth log line and return (timestamp(datetime or None), ip or None, event_type).
    Example:
    Mar 10 13:58:01 host1 sshd[1023]: Failed password for invalid user admin from 203.0.113.45 port 52344 ssh2
    """
    parts = line.split()
    if len(parts) < 3:
        return None, None, "other"
    # timestamp: first 3 tokens 'Mar 10 13:58:01'
    ts_str = " ".join(parts[0:3])
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        # if parsing fails, return None so caller can skip
        return None, None, "other"

    event_type = "other"
    if "Failed password" in line:
        event_type = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted"

    ip = None
    # safer extraction: search for token "from" then next token if exists and looks like IP
    if " from " in line:
        try:
            idx = parts.index("from")
            if idx + 1 < len(parts):
                ip_candidate = parts[idx + 1]
                # strip potential trailing punctuation
                ip_candidate = ip_candidate.strip(",;")
                ip = ip_candidate
        except ValueError:
            ip = None

    return ts, ip, event_type


def brute_force(per_ip_timestamps, max_minutes=10, threshold=5):
    """
    Sliding window detection. For each IP, find windows of length max_minutes
    with >= threshold failed attempts. Return list of incidents.
    Each incident is a dict: {"ip","count","first","last"}
    """
    sus_incidents = []
    window = timedelta(minutes=max_minutes)

    for ip, times in per_ip_timestamps.items():
        # ensure times sorted
        times.sort()
        n = len(times)
        i = 0
        while i < n:
            j = i
            # expand j as far as possible while within window relative to times[i]
            while j + 1 < n and (times[j + 1] - times[i]) <= window:
                j += 1
            count = j - i + 1
            if count >= threshold:
                sus_incidents.append({
                    "ip": ip,
                    "count": count,
                    "first": times[i].isoformat(),
                    "last": times[j].isoformat()
                })
                # advance i past this cluster to avoid overlapping duplicates
                i = j + 1
            else:
                i += 1

    return sus_incidents


def print_incidents_preview(sus_incidents, preview=5):
    print(f"Detected {len(sus_incidents)} brute-force incidents")
    for incident in sus_incidents[:preview]:
        print(incident)
    if len(sus_incidents) > preview:
        print("...")


def main():
    # Build per-ip timestamps
    per_ip_timestamps = defaultdict(list)

    try:
        with open(LOGFILE, "r") as fh:
            for line in fh:
                ts, ip, event = parse_auth_line(line)
                if ts and ip and event == "failed":
                    per_ip_timestamps[ip].append(ts)
    except FileNotFoundError:
        print(f"ERROR: Log file '{LOGFILE}' not found. Make sure it's in the current directory.", file=sys.stderr)
        sys.exit(1)

    # quick summary of failures per IP
    if not per_ip_timestamps:
        print("No failed-auth entries found in the log.")
    else:
        print("Failed attempts per IP (counts):")
        for ip, times in per_ip_timestamps.items():
            print(f"  {ip}: {len(times)} failed attempts")

    # detect incidents
    sus_incidents = brute_force(per_ip_timestamps, max_minutes=10, threshold=5)

    # print preview
    print()
    print_incidents_preview(sus_incidents, preview=5)

    # save full incidents to file
    with open("bruteforce_incidents.txt", "w") as out:
        json.dump(sus_incidents, out, indent=2)
    print("Saved detailed incidents to bruteforce_incidents.txt")

    # Aggregate totals per IP (sum of counts from incidents)
    summary = {}
    for inc in sus_incidents:
        summary[inc["ip"]] = summary.get(inc["ip"], 0) + inc["count"]

    # If there were no incidents but there were failed attempts, consider summarizing by raw counts:
    if not summary and per_ip_timestamps:
        # fallback: total failed attempts per ip
        summary = {ip: len(times) for ip, times in per_ip_timestamps.items()}

    # sort top attackers
    top_attackers = sorted(summary.items(), key=lambda x: x[1], reverse=True)

    if top_attackers:
        print("\nTop attacker IPs:")
        for ip, count in top_attackers[:10]:
            print(f"  {ip}: {count} failed attempts")
    else:
        print("\nNo attackers to summarize.")

    # Try plotting if matplotlib available and there is data
    if top_attackers:
        try:
            import matplotlib.pyplot as plt
            ips = [ip for ip, cnt in top_attackers[:10]]
            counts = [cnt for ip, cnt in top_attackers[:10]]
            plt.figure(figsize=(8, 4))
            plt.bar(ips, counts)
            plt.title("Top attacker IPs")
            plt.xlabel("IP")
            plt.ylabel("Failed attempts")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig("top_attackers.png")
            print("Saved bar chart to top_attackers.png")
            plt.show()
        except Exception as e:
            print(f"Matplotlib plotting skipped due to error: {e}", file=sys.stderr)
            print("If you want plotting, ensure matplotlib is installed in the interpreter used to run this script.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
