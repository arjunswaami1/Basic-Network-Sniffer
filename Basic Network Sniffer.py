import logging

from scapy.arch import get_if_list
from scapy.config import conf

# Suppress the warning about libpcap not being available
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Display the banner at the start of the program
print("""Your banner message""")

print("The Sniffer is waiting...")
print("")

def capture_traffic(net_iface):
    for iface in get_if_list():
        if iface == net_iface:
            sniff_socket = conf.L3socket(iface=iface)
            sniff_socket.ins.listen(0)  # Set the socket to non-blocking
            while True:
                p = sniff_socket.recv(MTU)  # Adjust MTU according to your needs
                analyze_packet(p)


def analyze_packet(pkt):
    if pkt.haslayer("IP"):
        ip_source = pkt["IP"].src
        ip_destination = pkt["IP"].dst
        protocol_num = pkt["IP"].proto

        display_message(f"SRC IP: {ip_source}, DEST IP: {ip_destination}, Protocol: {protocol_num}")

        if pkt.haslayer("TCP"):
            src_port = pkt["TCP"].sport
            dest_port = pkt["TCP"].dport
            display_message(f"TCP SRC Port: {src_port}, TCP DEST Port: {dest_port}")

        elif pkt.haslayer("UDP"):
            src_port = pkt["UDP"].sport
            dest_port = pkt["UDP"].dport
            display_message(f"UDP SRC Port: {src_port}, UDP DEST Port: {dest_port}")

        display_message("\n")


def display_message(msg):
    print(msg)


# Interface to monitor - change as needed (e.g., "eth0", "wlan0")
monitor_iface = "ens33"

# Adjust the MTU according to your network requirements
MTU = 1500

# Initiate packet capture
capture_traffic(monitor_iface)
