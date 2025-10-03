import json
import matplotlib.pyplot as plt

# Write incidents to file
with open('bruteforce_incidents.txt', 'w') as f:
    json.dump(incidents, f, indent=2)

# Aggregate total counts per IP from incidents
summary = {}
for inc in incidents:
    summary[inc['ip']] = summary.get(inc['ip'], 0) + inc['count']

# Sort top attackers
top_attackers = sorted(summary.items(), key=lambda x: x[1], reverse=True)

print("Top attackers IPs:")
for ip, count in top_attackers[:10]:
    print(f"{ip}: {count} failed attempts")
    
# A bar chart of top 10 attacker Ips 
print("A bar chart of top 10 attacker Ips)
ips = [ip for ip, count in top_attackers[:10]]
counts = [count for ip, count in top_attackers[:10]]

plt.figure(figsize=(8, 4))
plt.bar(ips, counts)
plt.title("Top attacker IPs")
plt.xlabel("IP")
plt.ylabel("Failed attempts")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("top_attackers.png")
plt.show()
