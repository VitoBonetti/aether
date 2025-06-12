import json
from scapy.all import rdpcap, PacketList
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, RadioTap
from pathlib import Path
from helpers.resolve_mac import resolve_mac
from datetime import datetime


def extract_probes(packets: PacketList, output_dir: str):
    print(f"Extracting probes")
    # if isinstance(pcap_filename, (list, tuple)):
    #     first = pcap_filename[0]
    #     # If it's a FilePickerFile-like with a .path attribute, unwrap it
    #     pcap_filename = getattr(first, 'path', first)
    # packets = rdpcap(pcap_filename)
    probes = []
    for pkt in packets:
        if pkt.haslayer(Dot11ProbeReq):
            ts = datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S')
            ssid = pkt.info.decode(errors='ignore') if pkt.info else ''
            signal = None
            if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                signal = pkt[RadioTap].dBm_AntSignal
            station = pkt.addr2.lower()
            vendor = resolve_mac(station)
            probes.append({
                'timestamp': ts,
                'station': station,
                'vendor': vendor,
                'ssid': ssid,
                'signal': signal
            })

    out_path = Path(f"{output_dir}/probe_requests.json")
    with open(out_path, 'w') as f:
        json.dump(probes, f, indent=2)
    print(f"Wrote probe requests: {out_path}")
