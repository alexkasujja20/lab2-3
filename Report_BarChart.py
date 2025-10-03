import matplotlib.pyplot as plt
# sample data
ips = ['203.0.113.45','203.0.113.46','198.51.100.99']
counts = [45, 32, 20]
plt.figure(figsize=(8,4))
plt.bar(ips, counts)
plt.title("Top attacker IPs")
plt.xlabel("IP")
plt.ylabel("Failed attempts")
plt.tight_layout()
plt.savefig("top_attackers.png")
plt.show()
