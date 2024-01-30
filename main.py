from scapy.all import sniff
import psutil   # for the network interfaces

# to find and print network interfaces
addrs = psutil.net_if_addrs()
interface_names = list(addrs.keys())

print("Network Interfaces:")
print(interface_names)

interface = input("Enter the interface you would like to sniff on : ")

# Sniff Beacon frames on the "en0" interface in monitor mode
a = sniff(iface=interface, prn=lambda x: x.summary(), filter="tcp", count=3)
print(a)