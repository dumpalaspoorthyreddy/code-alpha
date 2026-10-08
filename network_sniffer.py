from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def process_packet(packet):
    """Display useful information from IPv4 packets."""
    if IP not in packet:
        return

    source = packet[IP].src
    destination = packet[IP].dst

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    else:
        protocol = "Other"

    print("\n" + "-" * 50)
    print(f"Source IP      : {source}")
    print(f"Destination IP : {destination}")
    print(f"Protocol       : {protocol}")

    if Raw in packet:
        payload = bytes(packet[Raw].load)
        # Limit displayed data to avoid dumping large packet contents.
        print(f"Payload (first 100 bytes): {payload[:100]!r}")

print("CodeAlpha - Basic Network Sniffer")
print("Capturing IPv4 packets...")
print("Press Ctrl+C to stop.\n")

try:
    sniff(prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\nSniffer stopped by user.")
