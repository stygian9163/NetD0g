from scapy.all import sniff
import psutil   # for the network interfaces
from scapy.layers.inet import IP, TCP, UDP, Ether   # to check for protocols
import time     # for the date / time stamp

# to find and print network interfaces
addrs = psutil.net_if_addrs()
interface_names = list(addrs.keys())
print("Network Interfaces:")
print(interface_names)

# a lil questionare for SNIFF parameters
interface = input("Enter the interface you would like to sniff on : ")
fil = input(">> Filter (tcp and port 60) : ")
count = int(input(">> Packet count to capture (default 3): "))

# the call back function for the captured packets
def packet_callback(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    src_ip = packet[Ether].src
    dst_ip = packet[Ether].dst

    protocol = "Unknown"
    port = "Unknown"

    if IP in packet:
        layer = packet[IP].payload
        if layer.name == "TCP":
            protocol = "TCP"
            port = layer.dport
        elif layer.name == "UDP":
            protocol = "UDP"
            port = layer.dport

    print(f"{timestamp} || {src_ip} -> {dst_ip} || protocol: {protocol} || port: {port}")


# Sniff Beacon frames on the supplied interface in monitor mode
a = sniff(prn=packet_callback, iface=interface, filter=fil, count=count)
