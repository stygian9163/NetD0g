import scapy.utils
from scapy.all import sniff
import psutil   # for the network interfaces
from scapy.layers.inet import IP, TCP, UDP, Ether  # to check for protocols
import time     # for the date / time stamp


# Find and print network interfaces
addrs = psutil.net_if_addrs()
interface_names = list(addrs.keys())
print("Network Interfaces:")
print(interface_names)


# A little questionnaire for SNIFF parameters with default values
interface = input(">> Enter the interface you would like to sniff on: ") or "en0"
fil = input(">> Filter (tcp and port 60): ")
count_input = input(">> Packet count to capture (default 3): ")
count = int(count_input) if count_input.strip() else 3
# List to store captured packets
captured_packets = []


# The callback function for the captured packets
def packet_callback(packet):
    # Add the packet to the list
    captured_packets.append(packet)

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # Extract source and destination addresses
    if IP in packet:  # Check if it's IPv4
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif hasattr(packet, "payload") and hasattr(packet.payload, "name") and packet.payload.name == "IPv6":
        # Check if it's IPv6
        src_ip = packet.payload.src
        dst_ip = packet.payload.dst
    else:
        return  # Ignore non-IPv4 and non-IPv6 packets

    protocol = "Unknown"
    port = "Unknown"

    # Check if it's a TCP or UDP packet
    if TCP in packet:
        layer = packet[TCP].payload
        protocol = "TCP"
        port = packet[TCP].dport
    elif hasattr(packet, "payload") and hasattr(packet.payload, "name") and packet.payload.name == "UDP":
        protocol = "UDP"
        port = packet[UDP].dport

    # Print detailed information about the packet
    print(f"{timestamp} || {src_ip} -> {dst_ip} || protocol: {protocol} || port: {port}")


# Sniff packets on the specified interface in monitor mode
pkts = sniff(prn=packet_callback, iface=interface, filter=fil, count=count)

# Prompt the user to choose a packet for detailed information
while True:
    choice = input("Choose from the menu:\nA >> Detailed info\nB >> Hex dump"
                   "\nC >> Save to pcap\nD >> Read pcap\nE >> Exit \n <<")

    if choice.lower() == "a":
        try:
            selected_index = int(input("Enter the index of the packet to show details: "))
            selected_packet = captured_packets[selected_index]
            print("---------------------\n" + selected_packet.summary())
            print("Selected Packet Details:")
            selected_packet.show()
            print("----------------------")
        except (ValueError, IndexError):
            print("Invalid index.")
    elif choice.lower() == "b":
        try:
            selected_index = int(input("Enter the index of the packet to show details: "))
            selected_packet = captured_packets[selected_index]
            print("----------------------\n" + selected_packet.summary())
            print("Selected Packet Hex Dump:")
            scapy.utils.hexdump(selected_packet)
            print("----------------------")
        except (ValueError, IndexError):
            print("Invalid index.")
    elif choice.lower() == "c":
        name = input("Write name for saved file: ")
        name = name + ".cap"
        scapy.utils.wrpcap(name, captured_packets)
    elif choice.lower() == "d":
        name = input("Write name for saved file: ")
        name = name + ".cap"
        scapy.utils.rdpcap(name, captured_packets)
    elif choice.lower() == "e":
        exit(0)
    else:
        print("Invalid choice. Please enter a valid option.")

