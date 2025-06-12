import json
from scapy.all import rdpcap, PacketList
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from helpers.resolve_mac import resolve_mac
from mac_vendor_lookup import MacLookup


def extract_networks(packets: PacketList, out_path: str):
    """
    Extracts two JSON files:
    1. merged_networks.json: SSIDs mapped to latest AP info.
    2. extended_networks.json: same, but each AP entry includes a list of connected clients with stats.
    """
    # ml = MacLookup()
    # # Update database
    # print("try to update")
    # try:
    #     ml.update_vendors()
    #     print("updating")
    # except:
    #     print("updating skip")
    #     pass

    # --- Phase 1: Collect beacons for AP info ---
    print("[*] Phase 1: Collect beacons for AP info")
    networks = {}  # ssid -> bssid -> ap info
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Beacon].network_stats().get('ssid', '')
            bssid = pkt.addr2.lower()
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get('channel')
            enc_info = stats.get('crypto')
            enc = list(enc_info) if isinstance(enc_info, set) else enc_info
            hidden = (ssid == '')

            # Signal strength
            signal = None
            if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                signal = pkt[RadioTap].dBm_AntSignal

            # Frequency / band
            frequency = None
            if pkt.haslayer(RadioTap):
                rt = pkt[RadioTap]
                ch_field = rt.fields.get('Channel') or rt.fields.get('channel')
                if isinstance(ch_field, tuple) and len(ch_field) >= 1:
                    frequency = ch_field[0]
            if frequency is None and channel:
                frequency = (2407 + channel*5) if channel <= 14 else (5000 + channel*5)
            if frequency is not None:
                band = 2.4 if frequency < 3000 else (5 if frequency < 6000 else 6)
            else:
                band = None

            last_seen = datetime.fromtimestamp(float(pkt.time)).strftime('%d-%m-%Y %H:%M:%S')
            bssid_resolved = resolve_mac(bssid)
            entry = {
                'bssid': bssid_resolved,
                'channel': channel,
                'signal': signal,
                'frequency': frequency,
                'band': band,
                'encryption': enc,
                'hidden': hidden,
                'last_seen': last_seen
            }

            networks.setdefault(ssid, {})
            prev = networks[ssid].get(bssid)
            if not prev or datetime.strptime(entry['last_seen'], '%d-%m-%Y %H:%M:%S') > datetime.strptime(prev['last_seen'], '%d-%m-%Y %H:%M:%S'):
                networks[ssid][bssid] = entry

    # --- Phase 2: Discover clients by inspecting Data frames ---
    print("[*] Phase 2: Discover clients by inspecting Data frames")
    print("[*] Creating clients map")
    print("[*] bssid -> client_mac -> client info")
    print(f"[>] Identify AP BSSID in addr3 for packet")
    print("[>] Determine client MAC")
    print("[>] Resolve MAC address")
    print("[>] Capture last seen & signal")
    # bssid -> client_mac -> client info
    clients_map = defaultdict(dict)
    for pkt in packets:
        if pkt.haslayer(Dot11) and pkt.type == 2:  # Data frame
            addr1 = pkt.addr1 and pkt.addr1.lower()
            addr2 = pkt.addr2 and pkt.addr2.lower()
            addr3 = pkt.addr3 and pkt.addr3.lower()
            # Identify AP BSSID in addr3
            if addr3 in {b for ss in networks.values() for b in ss}:
                bssid = addr3
                # Determine client MAC
                client_mac = None
                if addr2 == bssid:
                    client_mac = addr1
                elif addr1 == bssid:
                    client_mac = addr2
                if client_mac:
                    mac_resolved = resolve_mac(client_mac)
                    # Capture last seen & signal
                    client_time = datetime.fromtimestamp(float(pkt.time)).strftime('%d-%m-%Y %H:%M:%S')
                    client_entry = {'mac': mac_resolved, 'last_seen': client_time}
                    if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                        client_entry['signal'] = pkt[RadioTap].dBm_AntSignal
                    clients_map[bssid][mac_resolved] = client_entry

    # --- Phase 3: Write merged and extended JSON outputs ---
    # 1. merged_networks.json
    print("[*] Phase 3: Write merged and extended JSON outputs")
    merged = {ssid: list(aps.values()) for ssid, aps in networks.items()}
    out1 = Path(out_path) / 'merged_networks.json'
    with open(out1, 'w') as f:
        json.dump(merged, f, indent=2)

    # 2. extended_networks.json
    extended = {}
    for ssid, aps in merged.items():
        extended[ssid] = []
        for ap in aps:
            bssid = ap['bssid']
            ap_ext = ap.copy()
            # Attach clients list (maybe empty)
            ap_ext['clients'] = list(clients_map.get(bssid, {}).values())
            extended[ssid].append(ap_ext)

    out2 = Path(out_path) / 'extended_networks.json'
    with open(out2, 'w') as f:
        json.dump(extended, f, indent=2)

    print(f"[+] Wrote: {out1}\n[+] Wrote: {out2}")
