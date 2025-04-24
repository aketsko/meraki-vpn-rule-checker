import ipaddress

def build_object_location_map(objects_data, groups_data, extended_data):
    import ipaddress

    object_location_map = {}
    vpn_subnets_per_network = {}

    # Build network -> list of (subnet, useVpn)
    for net_id, details in extended_data.get("network_details", {}).items():
        network_name = details.get("network_name", net_id)
        subnets = details.get("vpn_settings", {}).get("subnets", [])
        subnet_entries = [(s.get("localSubnet", ""), s.get("useVpn", False)) for s in subnets if s.get("localSubnet")]
        vpn_subnets_per_network[network_name] = subnet_entries

    all_entries = []
    # Flatten all subnets from vpn_subnets_per_network into ip_network objects for containment checking
    declared_subnets = []
    for net_name, entries in vpn_subnets_per_network.items():
        for subnet, use_vpn in entries:
            try:
                net = ipaddress.ip_network(subnet.strip(), strict=False)
                declared_subnets.append((net, net_name, use_vpn))
            except ValueError:
                continue

    # Match objects to actual subnets from the vpn settings
    for obj in objects_data:
        cidr = obj.get("cidr")
        if not cidr:
            continue
        try:
            obj_net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue

        matches = []
        for net, net_name, use_vpn in declared_subnets:
            if obj_net.subnet_of(net) or net.subnet_of(obj_net) or obj_net == net:
                entry = {"network": net_name, "useVpn": use_vpn}
                matches.append(entry)
                all_entries.append(entry)

        if matches:
            object_location_map[cidr] = matches

    # ✅ ENSURE EVERY SUBNET is in the map
    for net, net_name, use_vpn in declared_subnets:
        cidr_str = str(net)
        entry = {"network": net_name, "useVpn": use_vpn}
        object_location_map.setdefault(cidr_str, []).append(entry)
        all_entries.append(entry)


    # Match group entries based on member objects
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
                for entry in object_location_map.get(obj_cidr, []):
                    tup = (entry["network"], entry["useVpn"])
                    if tup not in seen:
                        seen.add(tup)
                        entries.append(entry)
        if entries:
            object_location_map[group_key] = entries
    # Add fallback for "any"
    if all_entries:
        object_location_map["0.0.0.0/0"] = list({(e["network"], e["useVpn"]): e for e in all_entries}.values())

    return object_location_map


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


def is_exact_subnet_match(search_cidr, rule_cidrs):
    import ipaddress
    try:
        search_net = ipaddress.ip_network(search_cidr, strict=False)
        for rule_cidr in rule_cidrs:
            rule_net = ipaddress.ip_network(rule_cidr, strict=False)
            if search_net.subnet_of(rule_net) or search_net == rule_net:
                return True
        return False
    except ValueError:
        return False


def match_input_to_rule(rule_cidrs, input_cidr):
    try:
        input_net = ipaddress.ip_network(input_cidr, strict=False)
    except ValueError:
        return False

    for rule in rule_cidrs:
        try:
            rule_net = ipaddress.ip_network(rule, strict=False)
            if rule_net.overlaps(input_net) or rule_net.supernet_of(input_net) or rule_net.subnet_of(input_net):
                return True
        except ValueError:
            continue
    return False


def find_object_locations(input_list, object_location_map):
    results = []
    seen = set()

    for entry in input_list:
        try:
            ip_net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            print(f"[WARN] Invalid CIDR/IP in input: {entry}")
            continue

        best_match = None
        best_len = -1

        for cidr, mappings in object_location_map.items():
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if ip_net.subnet_of(net) or ip_net == net:
                    if net.prefixlen > best_len:
                        best_match = mappings
                        best_len = net.prefixlen
            except ValueError:
                continue

        if best_match:
            print(f"[MATCH] {entry} → {best_len}-bit match")
            for match in best_match:
                key = (match["network"], match["useVpn"])
                if key not in seen:
                    seen.add(key)
                    results.append(match)
        else:
            print(f"[MISS] {entry} did not match any known subnet")

    return {(entry["network"], entry["useVpn"]) for entry in results if isinstance(entry, dict)}



def evaluate_rule_scope_from_inputs(source_cidrs, dest_cidrs, obj_location_map):
    import ipaddress

    src_locs = find_object_locations(source_cidrs, obj_location_map)
    dst_locs = find_object_locations(dest_cidrs, obj_location_map)
    shared_networks = {s[0] for s in src_locs} & {d[0] for d in dst_locs}
    shared_locs = {(net, True) for net in shared_networks if (net, True) in src_locs or (net, True) in dst_locs}
    shared_locs |= {(net, False) for net in shared_networks if (net, False) in src_locs or (net, False) in dst_locs}


    # Extract VPN-enabled location names
    src_vpn_locs = {loc for (loc, vpn) in src_locs if vpn}
    dst_vpn_locs = {loc for (loc, vpn) in dst_locs if vpn}

    # Detect if user input is broad
    def is_supernet_or_any(cidr_list):
        try:
            return (
                "0.0.0.0/0" in cidr_list or
                any(ipaddress.ip_network(c).prefixlen < 24 for c in cidr_list)
            )
        except Exception:
            return False

    src_is_supernet = is_supernet_or_any(source_cidrs)
    dst_is_supernet = is_supernet_or_any(dest_cidrs)

    # Decide if VPN rules are needed
    vpn_needed = (
        bool(src_vpn_locs and dst_vpn_locs) and
        (
            src_vpn_locs.isdisjoint(dst_vpn_locs) or
            src_is_supernet or dst_is_supernet
        )
    )

    # Decide if local rules are needed
    local_needed = (
        bool(shared_locs) or
        (src_locs and not dst_locs) or
        (dst_locs and not src_locs) or
        src_is_supernet or dst_is_supernet
    )


    # Decide which locations to use for local rule filtering
    if shared_locs:
        local_rule_locations = shared_locs
    elif src_locs and not dst_locs:
        local_rule_locations = src_locs
    elif dst_locs and not src_locs:
        local_rule_locations = dst_locs
    elif src_is_supernet or dst_is_supernet:
        local_rule_locations = {
            (entry["network"], entry["useVpn"])
            for locs in obj_location_map.values()
            for entry in locs if isinstance(entry, dict)
        }
    else:
        local_rule_locations = set()


    return {
        "src_location_map": src_locs,
        "dst_location_map": dst_locs,
        "shared_locations": shared_locs,
        "vpn_needed": vpn_needed,
        "local_needed": local_needed,
        "local_rule_locations": list(local_rule_locations)
    }



def resolve_to_cidrs_supernet_aware(id_list, object_map, group_map):
    import ipaddress

    known_cidrs = set()
    for obj in object_map.values():
        cidr = obj.get("cidr")
        if cidr:
            try:
                known_cidrs.add(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue

    resolved = set()

    for entry in id_list:
        entry = entry.strip()
        if entry.lower() == "any":
            resolved.add("0.0.0.0/0")
            continue
        elif entry.startswith("OBJ(") and entry.endswith(")"):
            obj = object_map.get(entry[4:-1])
            if obj and "cidr" in obj:
                resolved.add(obj["cidr"])
        elif entry.startswith("GRP(") and entry.endswith(")"):
            grp = group_map.get(entry[4:-1])
            if grp:
                for m in grp.get("objectIds", []):
                    obj = object_map.get(str(m))
                    if obj and "cidr" in obj:
                        resolved.add(obj["cidr"])
        else:
            try:
                input_net = ipaddress.ip_network(entry, strict=False)
                for known in known_cidrs:
                    if known.overlaps(input_net):
                        resolved.add(str(known))
                # Always include exact match if registered
                if input_net in known_cidrs:
                    resolved.add(str(input_net))
            except ValueError:
                continue

    return list(resolved)

