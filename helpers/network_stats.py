import json
from pathlib import Path


def network_stats(output_path):
    input_path = Path(f'{output_path}/merged_networks.json')
    with open(input_path) as json_file:
        network = json.load(json_file)
    network_stats_json = {}
    channel_count = {}
    encryption_count = {}
    band_count = {}
    total_ssid = len(network)
    total_aps = sum(len(aps) for aps in network.values())

    for aps in network.values():
        for ap in aps:
            channel = ap.get("channel")
            channel_count[channel] = channel_count.get(channel, 0) + 1
            for encryption in ap.get("encryption", []):
                encryption_count[encryption] = encryption_count.get(encryption, 0) + 1
            band = ap.get("band")
            if band is not None:
                band_count[band] = band_count.get(band, 0) + 1

    network_stats_json["total_ssid"] = total_ssid
    network_stats_json["total_aps"] = total_aps
    network_stats_json["channel_count"] = channel_count
    network_stats_json["encryption_count"] = encryption_count
    network_stats_json["band_count"] = band_count

    out_file = Path(f'{output_path}/network_stats.json')

    with open(out_file, 'w') as f:
        json.dump(network_stats_json, f, indent=2)
