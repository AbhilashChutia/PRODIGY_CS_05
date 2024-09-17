from scapy.all import sniff, IP, TCP, UDP, Raw

# Function to handle each packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"[+] IP Packet: {ip_src} -> {ip_dst} (Protocol: {proto})")

        # Check for TCP or UDP protocols
        if TCP in packet:
            print(f"  [+] TCP Packet: Source Port: {packet[TCP].sport}, Dest Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"  [+] UDP Packet: Source Port: {packet[UDP].sport}, Dest Port: {packet[UDP].dport}")
        
        # Payload extraction (if any)
        if packet.haslayer(Raw):
            print(f"  [+] Payload: {packet[Raw].load}")

# Start sniffing on the default interface
print("[*] Starting packet capture...")
sniff(prn=packet_callback, store=False)
