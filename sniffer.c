#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <unistd.h>

void process_packet(unsigned char *buffer, int size) {
    // Skip Ethernet header (14 bytes) to get IP header
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;

    // Extract source and destination IPs
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;

    printf("\n[+] Packet Captured:\n");
    printf("Source IP: %s\n", inet_ntoa(source.sin_addr));
    printf("Destination IP: %s\n", inet_ntoa(dest.sin_addr));

    // Check protocol type
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));
        printf("Protocol: TCP\n");
        printf("Source Port: %u\n", ntohs(tcph->source));
        printf("Destination Port: %u\n", ntohs(tcph->dest));
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));
        printf("Protocol: UDP\n");
        printf("Source Port: %u\n", ntohs(udph->source));
        printf("Destination Port: %u\n", ntohs(udph->dest));
    } else {
        printf("Protocol: Other\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    // Create raw socket to capture all Ethernet packets
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    printf("Simple C Packet Sniffer\n");
    printf("Starting packet capture on %s...\n", argv[1]);

    unsigned char buffer[65536]; // Buffer for packet data
    while (1) {
        int data_size = recvfrom(sock, buffer, 65536, 0, NULL, NULL);
        if (data_size < 0) {
            perror("Receive failed");
            close(sock);
            return 1;
        }
        process_packet(buffer, data_size);
    }

    close(sock);
    return 0;
}
