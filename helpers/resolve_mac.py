from mac_vendor_lookup import MacLookup


def resolve_mac(mac_address):
    ml = MacLookup()
    # extract oui part
    oui = mac_address[:8].replace(':', '').upper()
    # extract last 3 octets
    last_three_octets = ":".join(mac_address.split(':')[3:]).upper()

    try:
        vendor = ml.lookup(mac_address)
        if vendor:
            return f"{vendor}-{last_three_octets}"
        else:
            print("vendor not found")
            return mac_address
    except KeyError as e:
        print(f"vendor not found: keyerror {e}")
        return mac_address
    except Exception as e:
        f"vendor not found: exception {e}"
        return mac_address
