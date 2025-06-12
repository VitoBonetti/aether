import json
from scapy.all import PacketList
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL
from datetime import datetime
from pathlib import Path


def extract_handshakes(packets: PacketList):
    print(f"Extracting handshakes")
    sessions = {}
    for pkt in packets:
        if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
            dot = pkt[Dot11]
            addr1 = dot.addr1.lower()
            addr2 = dot.addr2.lower()
            # Determine roles: when station sends to AP, addr1 is AP, addr2 is STA
            ap = addr1 if pkt.haslayer(EAPOL) and pkt.addr2 != pkt.addr3 else pkt.addr3
            ap = ap.lower()
            client = addr2 if ap == addr1 else addr1

            ts = datetime.fromtimestamp(float(pkt.time)).strftime('%d-%m-%Y %H:%M:%S')
            direction = 'STA->AP' if addr2 != ap else 'AP->STA'
            raw = pkt[EAPOL].original.hex()

            key = (ap, client)
            sessions.setdefault(key, []).append({
                'timestamp': ts,
                'direction': direction,
                'raw': raw
            })

    # Filter for completed 4-way handshakes
    handshakes = []
    for (ap, client), frames in sessions.items():
        if len(frames) >= 4:
            handshakes.append({
                'ap': ap,
                'client': client,
                'frames': frames
            })
    print(handshakes[0])
    return handshakes


def classify_message(key_info: int):
    """
    Heuristic classification of 4-way handshake messages based on Key Information field bits.
    Uses masks:
      INSTALL = 0x0040, ACK = 0x0080, MIC = 0x0100, SECURE = 0x0200
    Returns 'M1' - 'M4' or 'unknown'.
    """
    install = bool(key_info & 0x0040)
    ack = bool(key_info & 0x0080)
    mic = bool(key_info & 0x0100)
    secure = bool(key_info & 0x0200)

    # M1: ACK, no MIC, no Secure, no Install
    if ack and not mic and not secure and not install:
        return "M1"
    # M2: MIC and Install
    if mic and install and not ack and not secure:
        return "M2"
    # M3: ACK, MIC, Secure
    if ack and mic and secure:
        return "M3"
    # M4: MIC, Secure, no ACK
    if mic and secure and not ack:
        return "M4"
    return "unknown"


def group_handshakes(data, output_dir: str):
    # Group by (ap, client)
    sessions = {}
    for entry in data:
        ap = entry.get('ap')
        client = entry.get('client')
        for frame in entry.get('frames', []):
            ts = datetime.strptime(frame['timestamp'], '%d-%m-%Y %H:%M:%S')
            raw_hex = frame['raw']
            # Parse key_info from raw hex: bytes[5:7]
            raw_bytes = bytes.fromhex(raw_hex)
            if len(raw_bytes) < 7:
                key_info = 0
            else:
                key_info = int.from_bytes(raw_bytes[5:7], 'big')
            msg = classify_message(key_info)
            record = {
                'timestamp': frame['timestamp'],
                'direction': frame['direction'],
                'message': msg,
                'key_info': hex(key_info),
                'raw': raw_hex
            }
            sessions.setdefault((ap, client), []).append((ts, record))

    # Build output list
    output = []
    for (ap, client), records in sessions.items():
        # Sort by timestamp
        sorted_recs = [r for _, r in sorted(records, key=lambda x: x[0])]
        output.append({
            'ap': ap,
            'client': client,
            'frames': sorted_recs
        })

    out_path = Path(f"{output_dir}/handshakes.json")
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"Wrote handshakes: {out_path}")
