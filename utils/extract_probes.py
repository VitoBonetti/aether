import json
from scapy.all import PacketList
from scapy.layers.dot11 import Dot11ProbeReq, RadioTap
from pathlib import Path
from helpers.resolve_mac import resolve_mac
from datetime import datetime


def extract_probes(packets: PacketList, output_dir: str):
    stations = {}

    print("[*] Phase 5: Extracting probes...")
    print(f"[*] Check if any packet is a Probe Request frame")
    print(f"[*] Extract SSID (may be empty if it's a broadcast probe)")
    print(f"[*] Try to extract signal strength (RSSI) if available")
    print(f"[*] Get the MAC address and try to resolve the vendor name ")
    print(f"[*] Store the most recent probe request per SSID ")
    print(f"[*] Working on it...")
    for pkt in packets:
        if pkt.haslayer(Dot11ProbeReq):
            ts = datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S')
            ssid = pkt.info.decode(errors='ignore') if pkt.info else ''
            signal = None
            if pkt.haslayer(RadioTap) and hasattr(pkt.getlayer(RadioTap), 'dBm_AntSignal'):
                signal = pkt.getlayer(RadioTap).dBm_AntSignal
            station = pkt.addr2.lower()
            vendor = resolve_mac(station)

            # Initialize station record
            if station not in stations:
                stations[station] = {'vendor': vendor, 'probes': {}}

            # Update only if newer
            prev = stations[station]['probes'].get(ssid)
            if not prev or ts > prev['timestamp']:
                stations[station]['probes'][ssid] = {'timestamp': ts, 'ssid': ssid, 'signal': signal}

    # Build final list
    print("[*] Prepare final output list")
    output = []
    for station, info in stations.items():
        probes_list = list(info['probes'].values())
        # Sort by timestamp, most recent first
        probes_list.sort(key=lambda x: x['timestamp'], reverse=True)
        output.append({'station': station, 'vendor': info['vendor'], 'probes': probes_list})

    out_path = Path(f"{output_dir}/probe_requests.json")
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"[+] Wrote probe requests: {out_path}")
