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

    for cidr in rule_cidrs:
        try:
            rule_net = ipaddress.ip_network(cidr.strip(), strict=False)

            # Case 1: input is a single IP — check if it's inside the rule's network
            if input_net.prefixlen == input_net.max_prefixlen:
                ip = ipaddress.ip_address(input_value.split("/")[0])
                if ip in rule_net:
                    return True

            # Case 2: input is a subnet — check if it is fully within the rule's subnet
            elif input_net.subnet_of(rule_net):
                return True

        except ValueError:
            continue

    return False
