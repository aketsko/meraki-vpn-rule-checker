import ipaddress


def evaluate_rule_scope_from_inputs(src_input, dst_input, object_map, group_map, object_location_map):
    from .match_logic import resolve_to_cidrs
    import ipaddress
    from collections import defaultdict

    # Normalize inputs
    if isinstance(src_input, str):
        src_ids = [src_input]
    elif isinstance(src_input, list):
        src_ids = src_input
    else:
        src_ids = []

    src_ids = ["0.0.0.0/0"] if not src_ids or any(x.strip().lower() == "any" for x in src_ids) else src_ids

    if isinstance(dst_input, str):
        dst_ids = [dst_input]
    elif isinstance(dst_input, list):
        dst_ids = dst_input
    else:
        dst_ids = []

    dst_ids = ["0.0.0.0/0"] if not dst_ids or any(x.strip().lower() == "any" for x in dst_ids) else dst_ids

    # Resolve to CIDRs
    src_cidrs = resolve_to_cidrs(src_ids, object_map, group_map)
    dst_cidrs = resolve_to_cidrs(dst_ids, object_map, group_map)

    # Map CIDRs to location + useVpn
    src_loc_map = defaultdict(list)
    dst_loc_map = defaultdict(list)

    for cidr in src_cidrs:
        if cidr in object_location_map:
            for entry in object_location_map[cidr]:
                src_loc_map[cidr].append(entry)

    for cidr in dst_cidrs:
        if cidr in object_location_map:
            for entry in object_location_map[cidr]:
                dst_loc_map[cidr].append(entry)

    # Decompose pairs
    vpn_needed = False
    local_locations = set()

    for sc in src_cidrs:
        for dc in dst_cidrs:
            src_entries = src_loc_map.get(sc, [])
            dst_entries = dst_loc_map.get(dc, [])

            if not src_entries or not dst_entries:
                # one or both unknown → evaluate local
                local_locations.update(entry["network"] for entry in src_entries + dst_entries)
                continue

            for se in src_entries:
                for de in dst_entries:
                    if se["useVpn"] and de["useVpn"]:
                        if se["network"] != de["network"]:
                            vpn_needed = True
                        else:
                            local_locations.add(se["network"])
                    else:
                        # One side not useVpn = treat as local only
                        if se["network"] == de["network"]:
                            local_locations.add(se["network"])

    return {
        "src_cidrs": src_cidrs,
        "dst_cidrs": dst_cidrs,
        "src_location_map": src_loc_map,
        "dst_location_map": dst_loc_map,
        "show_vpn_rules": vpn_needed,
        "show_local_rules": bool(local_locations),
        "local_locations": sorted(local_locations)
    }


def resolve_to_cidrs(input_list, object_map, group_map, visited=None):
    import ipaddress

    if visited is None:
        visited = set()

    resolved = set()

    for item in input_list:
        if item.lower() == "any":
            resolved.add("0.0.0.0/0")
            continue

        if item in visited:
            continue
        visited.add(item)

        # Direct CIDR or IP check
        try:
            ip_net = ipaddress.ip_network(item, strict=False)
            resolved.add(str(ip_net))
            continue
        except ValueError:
            pass

        # Object
        if item in object_map:
            for cidr in object_map[item]:
                try:
                    ip_net = ipaddress.ip_network(cidr, strict=False)
                    resolved.add(str(ip_net))
                except ValueError:
                    pass

        # Group (recurse)
        if item in group_map:
            nested_items = group_map[item]
            nested_resolved = resolve_to_cidrs(nested_items, object_map, group_map, visited)
            resolved.update(nested_resolved)

    return sorted(resolved)


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

def build_object_location_map(objects_data, groups_data, extended_data):
    import ipaddress
    object_location_map = {}
    vpn_subnets_per_network = {}

    for net_id, details in extended_data.get("network_details", {}).items():
        network_name = details.get("network_name", "")
        subnets = details.get("vpn_settings", {}).get("subnets", [])
        subnet_entries = [(s.get("localSubnet", ""), s.get("useVpn", False)) for s in subnets if s.get("localSubnet")]
        vpn_subnets_per_network[network_name] = subnet_entries

    # Map objects to matching networks (including useVpn)
    for obj in objects_data:
        cidr = obj.get("cidr")
        if not cidr:
            continue
        try:
            obj_net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            continue

        matches = []
        for net_name, subnet_entries in vpn_subnets_per_network.items():
            for subnet, use_vpn in subnet_entries:
                try:
                    vpn_net = ipaddress.ip_network(subnet.strip(), strict=False)
                    # Match if object is contained in or contains subnet
                    if obj_net.subnet_of(vpn_net) or vpn_net.subnet_of(obj_net) or obj_net == vpn_net:
                        matches.append({"network": net_name, "useVpn": use_vpn})
                except:
                    continue
        if matches:
            object_location_map[cidr] = matches

    # Map group entries
    for group in groups_data:
        group_id = group.get("id")
        member_ids = group.get("objectIds", [])
        group_key = f"GRP({group_id})"
        entries = []
        seen = set()
        for mid in member_ids:
            obj = next((o for o in objects_data if o.get("id") == mid), None)
            if obj:
                obj_cidr = obj.get("cidr")
                if obj_cidr and obj_cidr in object_location_map:
                    for entry in object_location_map[obj_cidr]:
                        tup = (entry["network"], entry["useVpn"])
                        if tup not in seen:
                            seen.add(tup)
                            entries.append(entry)
        if entries:
            object_location_map[group_key] = entries

    return object_location_map

