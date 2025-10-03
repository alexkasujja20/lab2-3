# lab2.3 Detect Brute-force Bursts 
import json
from collections import defaultdict
from datetime import datetime

LOGFILE = "sample_auth_small.log"

def parse_auth_line(line):
    """
    Parse an auth log line and return (timestamp, ip, event_type)
    Example auth line:
    Mar 10 13:58:01 host1 sshd[1023]: Failed password for invalid user admin from 203.0.113.45 port 52344 ssh2
    We will:
     - parse timestamp (assume year 2025)
     - extract IP (token after 'from')
     - event_type: 'failed' if 'Failed password', 'accepted' if 'Accepted password', else 'other'
    """
    parts = line.split()
    # timestamp: first 3 tokens 'Mar 10 13:58:01'
    ts_str = " ".join(parts[0:3])
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        ts = None
    ip = None
    event_type = "other"
    if "Failed password" in line:
        event_type = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted"
    if " from " in line:
        try:
            idx = parts.index("from")
            ip = parts[idx+1]
        except (ValueError, IndexError):
            ip = None
    return ts, ip, event_type
  
  def brute_force(per_ip_timestamps, max_minutes=10, threshold = 5):
  from datetime import timedelta

    sus_incidents = []
    window = timedelta(minutes=10)
    for ip, times in per_ip_timestamps.items():
        times.sort()
        n = len(times)
        i = 0
        while i < n:
            j = i
            # Expand window while the time difference is <=10 minutes
            while j + 1 < n and (times[j+1] - times[i]) <= window:
                j += 1
            count = j - i + 1
            if count >= threshold:
                incidents.append({
                    "ip": ip,
                    "count": count,
                    "first": times[i].isoformat(),
                    "last": times[j].isoformat()
                })
                # advance i past this cluster to avoid duplicate overlapping reports:
                i = j + 1
            else:
                i += 1
     print(f"Detected {len(incidents)} brute-force incidents")
     for incident in incidents[:5]:
         print(incident)

if __name__ == "__main__":
    per_ip_timestamps = defaultdict(list)
    with open(LOGFILE) as f:
        for line in f:
            ts, ip, event = parse_auth_line(line)
            if ts and ip and event == "failed":   # checks that ts and ip are not null, and that event=="failed"
                per_ip_timestamps[ip].append(ts)
    # quick print
    for ip, times in per_ip_timestamps.items():
        print(ip, len(times))
