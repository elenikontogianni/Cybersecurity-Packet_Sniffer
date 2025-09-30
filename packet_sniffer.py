from scapy.all import *
import sys

from scapy.layers.inet import TCP, UDP, IP


def packet_callback(packet):
 
    # Check if the packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # Initialize port variables
        src_port = dst_port = None

        # Check for TCP or UDP layers to get ports
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            proto_name = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            proto_name = "UDP"
        else:
            proto_name = "Other"

        # Print basic packet details
        print(f"\n[+] Packet Captured:")
        print(f"Source: {src_ip}:{src_port}")
        print(f"Destination: {dst_ip}:{dst_port}")
        print(f"Protocol: {proto_name}")

        if TCP in packet and packet[TCP].dport == 80:
            if Raw in packet:
                payload = packet[Raw].load
                try:
                    # Decode payload as text (HTTP is often readable)
                    print(f"HTTP Payload: {payload.decode('utf-8', errors='ignore')[:100]}...")
                except:
                    print("HTTP Payload: [Non-text or encrypted]")
        elif TCP in packet and packet[TCP].sport == 80:
            print("HTTP Response Packet Detected")

def start_sniffer(interface, filter_protocol="tcp port 80"):
 
    print(f"Starting packet sniffer on {interface}...")
    try:
        # Sniff packets with a filter (e.g., TCP port 80 for HTTP)
        sniff(iface=interface, prn=packet_callback, filter=filter_protocol, store=0)
    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":

    interface = "Wi-Fi"
    print("Packet Sniffer Mini Project")
    print("Ensure you have root/admin privileges to run this script.")
    start_sniffer(interface)
