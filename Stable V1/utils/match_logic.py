import ipaddress

def resolve_to_cidrs(id_list, object_map, group_map):
    cidrs = []
    for entry in id_list:
        entry = entry.strip()
        if entry == "Any":
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

def match_input_to_rule(rule_cidrs, search_input):
    try:
        search_net = ipaddress.ip_network(search_input, strict=False)
    except ValueError:
        return False
    for rule_cidr in rule_cidrs:
        try:
            rule_net = ipaddress.ip_network(rule_cidr.strip(), strict=False)
            if search_net.subnet_of(rule_net) or rule_net.subnet_of(search_net) or search_net == rule_net:
                return True
        except ValueError:
            continue
    return False

def is_exact_subnet_match(input_value, rule_cidrs):
    try:
        input_net = ipaddress.ip_network(input_value, strict=False)
    except ValueError:
        return False

    for rule_cidr in rule_cidrs:
        try:
            rule_net = ipaddress.ip_network(rule_cidr.strip(), strict=False)
            if input_net.subnet_of(rule_net) and input_net != rule_net:
                return True
            elif input_net == rule_net:
                return True
        except ValueError:
            continue
    return False

def find_object_locations(cidr_list, extended_data):
    locations = set()
    for net_id, net_info in extended_data.get("network_details", {}).items():
        vpn_subnets = net_info.get("vpn_settings", {}).get("subnets", [])
        subnet_cidrs = [s.get("localSubnet", "") for s in vpn_subnets if s.get("localSubnet")]
        for cidr in cidr_list:
            for subnet in subnet_cidrs:
                try:
                    cidr_net = ipaddress.ip_network(cidr.strip(), strict=False)
                    subnet_net = ipaddress.ip_network(subnet.strip(), strict=False)
                    if cidr_net.subnet_of(subnet_net) or cidr_net == subnet_net or subnet_net.subnet_of(cidr_net):
                        locations.add(net_info.get("network_name", net_id))
                except Exception:
                    continue
    return sorted(locations)

import ipaddress

def build_object_location_map(object_map, group_map, extended_data):
    object_location_map = {}
    network_map = extended_data.get("network_map", {})

    # Track which object CIDRs inherit from each network subnet
    for net_name, net_data in network_map.items():
        for subnet in net_data.get("subnets", []):
            supernet_cidr = subnet.get("localSubnet")
            use_vpn = subnet.get("useVpn", False)
            if not supernet_cidr:
                continue
            try:
                supernet = ipaddress.ip_network(supernet_cidr)
            except ValueError:
                continue

            # Direct entry
            object_location_map.setdefault(supernet_cidr, []).append({
                "network": net_name,
                "useVpn": use_vpn
            })

            # Check all object_map CIDRs that fall inside this supernet
            for obj in object_map.values():
                obj_cidr = obj.get("cidr")
                if not obj_cidr:
                    continue
                try:
                    ipnet = ipaddress.ip_network(obj_cidr)
                except ValueError:
                    continue
                if ipnet.subnet_of(supernet):
                    object_location_map.setdefault(obj_cidr, []).append({
                        "network": net_name,
                        "useVpn": use_vpn
                    })

    # Final fallback: map 0.0.0.0/0 to all known locations
    all_entries = []
    for entries in object_location_map.values():
        for e in entries:
            if e not in all_entries:
                all_entries.append(e)
    object_location_map["0.0.0.0/0"] = all_entries

    return object_location_map