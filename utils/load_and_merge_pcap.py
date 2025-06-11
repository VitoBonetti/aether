from scapy.all import rdpcap, PacketList


def load_and_merge_pcap(file_paths):
    all_packets = PacketList()
    print("Loading and merging pcap files...")
    for path in file_paths:
        print(path)
        all_packets.extend(rdpcap(path))
    print(f"Sorting {len(all_packets)} total packets by timestamp...")
    all_packets.sort(key=lambda p: p.time)
    print("Sorting complete.")

    return all_packets
