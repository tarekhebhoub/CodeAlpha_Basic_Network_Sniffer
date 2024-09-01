import argparse
from scapy.all import sniff, wrpcap, TCP, UDP, ICMP

# Callback function to process captured packets
captured_packets = []

def packet_callback(packet):
    # Print the captured packet summary
    print(packet.summary())
    # Append packet to the list for saving later
    captured_packets.append(packet)

# Capture packets based on the given protocol and save them to a file
def start_sniffing(interface, protocol_filter, output_file):
    print(f"[*] Starting packet sniffer on {interface} for {protocol_filter} packets...")
    
    # Sniff packets with the given protocol filter
    sniff(iface=interface, prn=packet_callback, filter=protocol_filter, store=False)
    
    # Save the captured packets to the specified file
    print(f"[*] Saving captured packets to {output_file}...")
    wrpcap(output_file, captured_packets)
    print(f"[*] Saved {len(captured_packets)} packets to {output_file}")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Network Sniffer with Protocol Filter and Packet Saving")
    parser.add_argument("protocol", help="Protocol type to filter (tcp, udp, icmp, etc.)", type=str)
    parser.add_argument("output_file", help="Name of the file to save captured packets", type=str)
    parser.add_argument("--interface", help="Network interface to sniff on (default: eth0)", type=str, default="eth0")

    args = parser.parse_args()

    # Extract arguments
    protocol_filter = args.protocol.lower()
    output_file = args.output_file
    interface = args.interface

    # Start sniffing with the specified parameters
    start_sniffing(interface, protocol_filter, output_file)
