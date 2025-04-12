import ipaddress

def build_object_location_map(object_map, group_map, extended_data):
    import ipaddress
    object_location_map = {}
    vpn_settings = extended_data.get("vpn_settings", [])

    # Extract all known object CIDRs
    known_cidrs = set()
    for obj in object_map.values():
        if 'cidr' in obj:
            known_cidrs.add(obj['cidr'])
    for group in group_map.values():
        for obj_id in group.get("objectIds", []):
            obj = object_map.get(str(obj_id))
            if obj and 'cidr' in obj:
                known_cidrs.add(obj['cidr'])

    # Build location map by matching CIDRs inside VPN subnets
    for vpn_entry in vpn_settings:
        net_name = vpn_entry.get("name")
        for subnet in vpn_entry.get("subnets", []):
            cidr = subnet.get("localSubnet")
            use_vpn = subnet.get("useVpn", False)
            try:
                vpn_net = ipaddress.ip_network(cidr)
            except ValueError:
                continue
            for obj_cidr in known_cidrs:
                try:
                    obj_net = ipaddress.ip_network(obj_cidr)
                    if obj_net.subnet_of(vpn_net):
                        object_location_map.setdefault(obj_cidr, []).append({
                            "network": net_name,
                            "useVpn": use_vpn
                        })
                except ValueError:
                    continue

    # Add catch-all 0.0.0.0/0 → all unique mappings
    all_entries = []
    for entries in object_location_map.values():
        for e in entries:
            if e not in all_entries:
                all_entries.append(e)
    object_location_map["0.0.0.0/0"] = all_entries

    return object_location_map
def find_object_locations(cidrs, object_location_map):
    locations = set()
    for cidr in cidrs:
        for key in object_location_map:
            try:
                if ipaddress.ip_network(cidr).subnet_of(ipaddress.ip_network(key)) or ipaddress.ip_network(key).subnet_of(ipaddress.ip_network(cidr)):
                    for entry in object_location_map[key]:
                        if isinstance(entry, dict):
                            locations.add(entry.get("network") or entry.get("location", ""))
                        elif isinstance(entry, str):
                            locations.add(entry)
            except ValueError:
                continue
    return locations



def resolve_to_cidrs(id_list, object_map, group_map):
    cidrs = []
    for entry in id_list:
        entry = entry.strip()
        if entry.lower() == "any":
            cidrs.append("0.0.0.0/0")
        elif entry.startswith("OBJ(") and entry.endswith(")"):
            obj = object_map.get(entry[4:-1])
            if obj and "cidr" in obj:
                cidrs.append(obj["cidr"])
        elif entry.startswith("GRP(") and entry.endswith(")"):
            grp = group_map.get(entry[4:-1])
            if grp:
                for m in grp.get("objectIds", []):
                    obj = object_map.get(str(m))
                    if obj and "cidr" in obj:
                        cidrs.append(obj["cidr"])
    return cidrs


def is_exact_subnet_match(search_cidr, rule_cidr):
    try:
        search_net = ipaddress.ip_network(search_cidr)
        rule_net = ipaddress.ip_network(rule_cidr)
        return search_net.subnet_of(rule_net)
    except ValueError:
        return False


def match_input_to_rule(input_cidrs, rule_cidrs):
    for input_cidr in input_cidrs:
        for rule_cidr in rule_cidrs:
            try:
                input_net = ipaddress.ip_network(input_cidr)
                rule_net = ipaddress.ip_network(rule_cidr)
                if input_net.overlaps(rule_net):
                    return True
            except ValueError:
                continue
    return False


def evaluate_rule_scope_from_inputs(source_cidrs, dest_cidrs, obj_location_map):
    src_locs = find_object_locations(source_cidrs, obj_location_map)
    dst_locs = find_object_locations(dest_cidrs, obj_location_map)
    shared_locs = src_locs & dst_locs

    src_vpn_locs = set()
    dst_vpn_locs = set()

    for cidr in source_cidrs:
        for entry in obj_location_map.get(cidr, []):
            if isinstance(entry, dict) and entry.get("useVpn"):
                src_vpn_locs.add(entry.get("network"))

    for cidr in dest_cidrs:
        for entry in obj_location_map.get(cidr, []):
            if isinstance(entry, dict) and entry.get("useVpn"):
                dst_vpn_locs.add(entry.get("network"))

    vpn_needed = bool(src_vpn_locs & dst_vpn_locs) and not shared_locs
    local_needed = bool(shared_locs or not vpn_needed)

    return {
        "src_location_map": src_locs,
        "dst_location_map": dst_locs,
        "shared_locations": shared_locs,
        "vpn_needed": vpn_needed,
        "local_needed": local_needed,
    }