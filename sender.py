from scapy.all import IP, ICMP, send

target_ip = "172.20.10.6"

icmp_packet = IP(dst=target_ip)/ICMP()/"this is my message"

send(icmp_packet)
