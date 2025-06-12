import json
from scapy.all import rdpcap, PacketList
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL
from datetime import datetime
from pathlib import Path

# --- Improved `classify_message` ---

# Key Information field bit masks for clarity, based on IEEE 802.11i
PAIRWISE_MASK = 0x0008  # Pairwise Key (PTK)
INSTALL_MASK = 0x0040  # Install
ACK_MASK = 0x0080  # Ack
MIC_MASK = 0x0100  # MIC
SECURE_MASK = 0x0200  # Secure


def classify_message(key_info: int):
    """
    Classifies a 4-way handshake message based on the Key Information field.

    This classification is based on the IEEE 802.11i standard. The logic checks
    for specific combinations of flags that uniquely identify each of the four
    messages in a successful handshake.

    - M1 (AP -> STA): Announces the handshake. Flags: Pairwise=1, ACK=1.
    - M2 (STA -> AP): Responds with SNonce and MIC. Flags: Pairwise=1, MIC=1.
    - M3 (AP -> STA): Delivers GTK and confirms sequence. Flags: Pairwise=1, ACK=1, MIC=1, Secure=1, Install=1.
    - M4 (STA -> AP): Final confirmation. Flags: Pairwise=1, MIC=1, Secure=1.

    Args:
        key_info (int): The 16-bit integer value of the Key Information field.

    Returns:
        str: 'M1', 'M2', 'M3', 'M4', or 'Unknown'.
    """
    is_pairwise = bool(key_info & PAIRWISE_MASK)
    install = bool(key_info & INSTALL_MASK)
    ack = bool(key_info & ACK_MASK)
    mic = bool(key_info & MIC_MASK)
    secure = bool(key_info & SECURE_MASK)

    # We only care about Pairwise Key (PTK) handshakes.
    if not is_pairwise:
        return "Unknown"

    # M3: Must be checked first as its flags are a superset of others.
    # It's the only message with Install=1, Secure=1, and ACK=1 set.
    if ack and mic and secure and install:
        return "M3"

    # M4: Final message from Station. Secure bit is set, but no Install or ACK.
    if mic and secure and not ack and not install:
        return "M4"

    # M2: Station to AP. Contains MIC but is not yet secure.
    # The original script incorrectly checked for the Install bit here.
    if mic and not ack and not secure and not install:
        return "M2"

    # M1: AP to Station. Acknowledges station's association. No MIC yet.
    if ack and not mic and not secure and not install:
        return "M1"

    return "Unknown"


# --- Improved `extract_handshakes` ---

def extract_handshakes(packets: PacketList):
    """
    Extracts all EAPOL frames from a packet list and groups them by AP/Client pair.
    This function is focused on robust extraction, leaving sequencing to group_handshakes.

    Args:
        packets (PacketList): A list of Scapy packets.

    Returns:
        dict: A dictionary where keys are (ap_mac, client_mac) tuples and
              values are lists of raw EAPOL frame data and timestamps.
    """
    print("Extracting all EAPOL frames...")
    sessions = {}
    for pkt in packets:
        if not (pkt.haslayer(EAPOL) and pkt.haslayer(Dot11)):
            continue

        try:
            dot = pkt[Dot11]
            # Robust AP/Client identification: In an infrastructure network,
            # addr3 (BSSID) is the most reliable AP MAC address.
            ap_mac = dot.addr3.lower()

            # The client is the other MAC address (not the AP).
            client_mac = dot.addr1.lower() if dot.addr2.lower() == ap_mac else dot.addr2.lower()

            if client_mac == ap_mac:  # Should not happen in a valid AP-STA EAPOL frame
                continue

            session_key = (ap_mac, client_mac)
            sessions.setdefault(session_key, []).append({
                'timestamp': datetime.fromtimestamp(float(pkt.time)),
                'raw': pkt[EAPOL].original
            })
        except (AttributeError, IndexError):
            # Skip malformed packets that lack expected fields.
            continue

    print(f"Found EAPOL frames for {len(sessions)} unique (AP, Client) pairs.")
    return sessions


# --- Improved `group_handshakes` ---

def group_handshakes(eapol_sessions: dict, output_dir: str):
    """
    Processes EAPOL frames, classifies them, and groups them into both
    complete and partial handshake sequences.

    Args:
        eapol_sessions (dict): Raw EAPOL frames grouped by (AP, Client) pair.
        output_dir (str): Directory to save the final JSON output.
    """
    print("Grouping frames into complete and partial handshakes...")
    all_handshakes = []

    for (ap, client), frames in eapol_sessions.items():
        enriched_frames = []
        for frame in frames:
            try:
                if len(frame['raw']) < 7:
                    continue
                key_info = int.from_bytes(frame['raw'][5:7], 'big')
                enriched_frames.append({
                    'timestamp': frame['timestamp'],
                    'message': classify_message(key_info),
                    'key_info': hex(key_info),
                    'raw': frame['raw'].hex()
                })
            except (IndexError, TypeError):
                continue

        sorted_frames = sorted(enriched_frames, key=lambda x: x['timestamp'])

        # State machine to find handshake sequences
        current_handshake = []
        expected_sequence = ['M1', 'M2', 'M3', 'M4']

        for frame in sorted_frames:
            msg_type = frame['message']

            # State 1: We are not currently building a handshake
            if not current_handshake:
                if msg_type == 'M1':
                    # Start a new handshake if we find an M1
                    current_handshake.append(frame)
                continue  # Ignore any other message if not in a handshake

            # State 2: We are already building a handshake
            expected_msg_index = len(current_handshake)
            expected_msg_type = expected_sequence[expected_msg_index]

            if msg_type == expected_msg_type:
                # Correct message in sequence, add it
                current_handshake.append(frame)
            elif msg_type == 'M1':
                # A new handshake started before the old one finished.
                # Save the old partial handshake.
                all_handshakes.append({'ap': ap, 'client': client, 'frames': current_handshake, 'status': 'Partial'})
                # Start the new handshake with the current M1 frame.
                current_handshake = [frame]
            else:
                # The sequence is broken by an unexpected/out-of-order message.
                # Save the partial handshake and reset.
                all_handshakes.append({'ap': ap, 'client': client, 'frames': current_handshake, 'status': 'Partial'})
                current_handshake = []

            # Check if the handshake just became complete
            if len(current_handshake) == 4:
                all_handshakes.append({'ap': ap, 'client': client, 'frames': current_handshake, 'status': 'Complete'})
                current_handshake = []

        # After the loop, if there's a handshake still being built, it's a final partial one.
        if current_handshake:
            all_handshakes.append({'ap': ap, 'client': client, 'frames': current_handshake, 'status': 'Partial'})

    # Format timestamps for all collected handshakes before writing to JSON
    for handshake in all_handshakes:
        for frame in handshake['frames']:
            frame['timestamp'] = frame['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')

    # Write output to a new file to distinguish it from the "complete only" version
    output_path = Path(output_dir) / "handshakes.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(all_handshakes, f, indent=2)

    print(f"Wrote {len(all_handshakes)} complete and partial handshakes to: {output_path}")
    return all_handshakes
# import json
# from scapy.all import PacketList
# from scapy.layers.dot11 import Dot11
# from scapy.layers.eap import EAPOL
# from datetime import datetime
# from pathlib import Path
#
#
# def extract_handshakes(packets: PacketList):
#     print(f"Extracting handshakes")
#     sessions = {}
#     for pkt in packets:
#         if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
#             dot = pkt[Dot11]
#             addr1 = dot.addr1.lower()
#             addr2 = dot.addr2.lower()
#             # Determine roles: when station sends to AP, addr1 is AP, addr2 is STA
#             ap = addr1 if pkt.haslayer(EAPOL) and pkt.addr2 != pkt.addr3 else pkt.addr3
#             ap = ap.lower()
#             client = addr2 if ap == addr1 else addr1
#
#             ts = datetime.fromtimestamp(float(pkt.time)).strftime('%d-%m-%Y %H:%M:%S')
#             direction = 'STA->AP' if addr2 != ap else 'AP->STA'
#             raw = pkt[EAPOL].original.hex()
#
#             key = (ap, client)
#             sessions.setdefault(key, []).append({
#                 'timestamp': ts,
#                 'direction': direction,
#                 'raw': raw
#             })
#
#     # Filter for completed 4-way handshakes
#     handshakes = []
#     for (ap, client), frames in sessions.items():
#         if len(frames) >= 4:
#             handshakes.append({
#                 'ap': ap,
#                 'client': client,
#                 'frames': frames
#             })
#     print(handshakes[0])
#     return handshakes
#
#
# def classify_message(key_info: int):
#     """
#     Heuristic classification of 4-way handshake messages based on Key Information field bits.
#     Uses masks:
#       INSTALL = 0x0040, ACK = 0x0080, MIC = 0x0100, SECURE = 0x0200
#     Returns 'M1' - 'M4' or 'unknown'.
#     """
#     install = bool(key_info & 0x0040)
#     ack = bool(key_info & 0x0080)
#     mic = bool(key_info & 0x0100)
#     secure = bool(key_info & 0x0200)
#
#     # M1: ACK, no MIC, no Secure, no Install
#     if ack and not mic and not secure and not install:
#         return "M1"
#     # M2: MIC and Install
#     if mic and install and not ack and not secure:
#         return "M2"
#     # M3: ACK, MIC, Secure
#     if ack and mic and secure:
#         return "M3"
#     # M4: MIC, Secure, no ACK
#     if mic and secure and not ack:
#         return "M4"
#     return "unknown"
#
#
# def group_handshakes(data, output_dir: str):
#     # Group by (ap, client)
#     sessions = {}
#     for entry in data:
#         ap = entry.get('ap')
#         client = entry.get('client')
#         for frame in entry.get('frames', []):
#             ts = datetime.strptime(frame['timestamp'], '%d-%m-%Y %H:%M:%S')
#             raw_hex = frame['raw']
#             # Parse key_info from raw hex: bytes[5:7]
#             raw_bytes = bytes.fromhex(raw_hex)
#             if len(raw_bytes) < 7:
#                 key_info = 0
#             else:
#                 key_info = int.from_bytes(raw_bytes[5:7], 'big')
#             msg = classify_message(key_info)
#             record = {
#                 'timestamp': frame['timestamp'],
#                 'direction': frame['direction'],
#                 'message': msg,
#                 'key_info': hex(key_info),
#                 'raw': raw_hex
#             }
#             sessions.setdefault((ap, client), []).append((ts, record))
#
#     # Build output list
#     output = []
#     for (ap, client), records in sessions.items():
#         # Sort by timestamp
#         sorted_recs = [r for _, r in sorted(records, key=lambda x: x[0])]
#         output.append({
#             'ap': ap,
#             'client': client,
#             'frames': sorted_recs
#         })
#
#     out_path = Path(f"{output_dir}/handshakes.json")
#     with open(out_path, 'w') as f:
#         json.dump(output, f, indent=2)
#     print(f"Wrote handshakes: {out_path}")
