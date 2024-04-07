from scapy.all import sniff, IP, ICMP

def handle_received_packet(packet):
    if packet[ICMP]: 
        print("Received ICMP packet from:", packet[IP].src)
        print("ICMP payload:", packet[ICMP].load)

def main():
    print("Sniffing for ICMP packets on all interfaces...")
    try:
        while True:  # loop to keep sniffing
            sniff(prn=handle_received_packet, filter="icmp",iface="en0")
    except KeyboardInterrupt:  
        print("\nStopping sniffing...")

if __name__ == "__main__":
    main()
