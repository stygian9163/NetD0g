from scapy.all import sniff
import psutil   # for the network interfaces

# to find and print network interfaces
addrs = psutil.net_if_addrs()
interface_names = list(addrs.keys())
print("Network Interfaces:")
print(interface_names)
interface = input("Enter the interface you would like to sniff on : ")
fil = input(">> Filter (tcp and port 60) : ")
count = int(input(">> Packet count to capture (default 3): "))


# Sniff Beacon frames on the "en0" interface in monitor mode
a = sniff(iface=interface, prn=lambda x: x.summary(), filter=fil, count=count)
print(a)