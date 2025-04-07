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
            # Exact only if search input is fully inside rule net
            if input_net.subnet_of(rule_net) and input_net != rule_net:
                return True
            elif input_net == rule_net:
                return True
        except ValueError:
            continue
    return False

def find_object_locations(cidr_list, extended_data):
    """
    Given a list of CIDRs and the extended Meraki data,
    return a sorted list of network names where any of these CIDRs match the VPN subnets.
    """
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

def build_object_location_map(objects_data, groups_data, extended_data):
    object_location_map = {}
    vpn_subnets_per_network = {}

    # Prepare VPN subnets per network
    for net_id, details in extended_data.get("network_details", {}).items():
        network_name = details.get("network_name", "")
        subnets = details.get("vpn_settings", {}).get("subnets", [])
        cidrs = [s.get("localSubnet", "") for s in subnets if "localSubnet" in s]
        vpn_subnets_per_network[network_name] = cidrs

    # Match objects to networks
    for obj in objects_data:
        obj_id = obj.get("id")
        obj_cidr = obj.get("cidr", "")
        if not obj_id or not obj_cidr:
            continue
        obj_networks = []
        for network_name, subnets in vpn_subnets_per_network.items():
            if any(match_input_to_rule([subnet], obj_cidr) for subnet in subnets):
                obj_networks.append(network_name)
        object_location_map[obj_id] = obj_networks

    # Match groups based on their members
    for grp in groups_data:
        group_id = grp.get("id")
        if not group_id:
            continue
        member_ids = grp.get("objectIds", [])
        seen = set()
        for mid in member_ids:
            for net in object_location_map.get(mid, []):
                seen.add(net)
        object_location_map[str(group_id)] = list(seen)

    return object_location_map
