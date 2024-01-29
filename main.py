from scapy.all import sniff

# Sniff Beacon frames on the "en0" interface in monitor mode
a = sniff(iface="en0", prn=lambda x: x.summary(), filter="tcp", count=3)
print(a)


