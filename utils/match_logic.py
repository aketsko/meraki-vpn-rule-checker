import ipaddress

def build_object_location_map(objects_data, groups_data, extended_data):
    object_location_map = {}
    vpn_subnets_per_network = {}

    for net_id, details in extended_data.get("network_details", {}).items():
        network_name = details.get("network_name", "")
        subnets = details.get("vpn_settings", {}).get("subnets", [])
        cidrs = [s.get("localSubnet", "") for s in subnets if "localSubnet" in s]
        vpn_subnets_per_network[network_name] = cidrs

    # Map object CIDRs to all matching networks
    for obj in objects_data:
        cidr = obj.get("cidr")
        if not cidr:
            continue
        try:
            obj_net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            continue

        matching_networks = set()
        for net_name, vpn_subnets in vpn_subnets_per_network.items():
            for subnet in vpn_subnets:
                try:
                    vpn_net = ipaddress.ip_network(subnet, strict=False)
                    if obj_net.subnet_of(vpn_net) or obj_net == vpn_net:
                        matching_networks.add(net_name)
                        break
                except:
                    continue
        if matching_networks:
            object_location_map[cidr] = sorted(matching_networks)
    # Add 0.0.0.0/0 mapped to all known subnets (catch-all)
    all_entries = []
    for cidr, entries in object_location_map.items():
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
                        if isinstance(entry, dict) and "network" in entry:
                            locations.add(entry["network"])
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
