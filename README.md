# Cybersecurity-Packet_Sniffer
A simple yet effective packet sniffer built with Python and Scapy to capture and analyze network traffic. This tool focuses on sniffing TCP and UDP packets, with special attention to HTTP traffic (port 80), and displays details like source/destination IP, ports, protocol, and payloads. Ideal for educational purposes, network debugging, or security analysis.
Features

Captures packets on a specified network interface.
Supports filtering for TCP, UDP, and HTTP (port 80) traffic.
Displays packet details, including:

Source and destination IP addresses and ports.
Protocol type (TCP, UDP, or other).
HTTP payloads (if available and decodable).


Lightweight and real-time with no packet storage.
Cross-platform (Linux, macOS, Windows) with Scapy.

Prerequisites

Python: Version 3.6 or higher.
Scapy: Install via pip install scapy.
Root/Administrator Privileges: Required for raw packet capture.
Network Interface: Must be specified (e.g., eth0, wlan0, Wi-Fi).
Usage

Run the Sniffer:
bashsudo python3 packet_sniffer.py

Replace sudo with runas or an admin Command Prompt on Windows.
The script defaults to the Wi-Fi interface and filters for TCP port 80 (HTTP).


Customize Interface and Filter:

Edit the interface variable in packet_sniffer.py to match your network interface.
Modify the filter_protocol in the start_sniffer function for different protocols (e.g., udp, tcp, port 443 for HTTPS).

