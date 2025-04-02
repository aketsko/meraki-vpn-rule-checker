
from typing import List, Union
import streamlit as st
import json
import ipaddress
import pandas as pd
import plotly.graph_objects as go
from io import BytesIO

# ------------------ PAGE SETUP ------------------
st.set_page_config(
    page_title="Meraki VPN Rule Checker",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# ------------------ SIDEBAR FILE UPLOAD ------------------
st.sidebar.header("🔧 Upload Configuration Files")
rules_file = st.sidebar.file_uploader("Upload Rules.json", type="json")
objects_file = st.sidebar.file_uploader("Upload Objects.json", type="json")
groups_file = st.sidebar.file_uploader("Upload Object Groups.json", type="json")

if not all([rules_file, objects_file, groups_file]):
    st.warning("Please upload all three JSON files to proceed.")
    st.stop()

rules_data = json.load(rules_file)["rules"]
objects_data = json.load(objects_file)
groups_data = json.load(groups_file)

# ------------------ HELPER FUNCTIONS ------------------
def safe_dataframe(data: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(data)
    for col in df.columns:
        df[col] = df[col].apply(lambda x: ", ".join(map(str, x)) if isinstance(x, list)
                                else str(x) if x is not None else "")
    return df

def get_object_map():
    return {obj["id"]: obj for obj in objects_data}

def get_group_map():
    return {grp["id"]: grp for grp in groups_data}

object_map = get_object_map()
group_map = get_group_map()

def resolve_entry(entry):
    networks = []
    if entry.startswith("OBJ("):
        obj_id = entry[4:-1]
        obj = object_map.get(obj_id)
        if obj and "cidr" in obj:
            try:
                networks.append(ipaddress.ip_network(obj["cidr"], strict=False))
            except ValueError:
                pass
    elif entry.startswith("GRP("):
        grp_id = entry[4:-1]
        members = group_map.get(grp_id, {}).get("objectIds", [])
        for m_id in members:
            obj = object_map.get(m_id)
            if obj and "cidr" in obj:
                try:
                    networks.append(ipaddress.ip_network(obj["cidr"], strict=False))
                except ValueError:
                    pass
    else:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass
    return networks

    
def id_to_name(entry):
    entry = entry.strip()
    if entry.startswith("OBJ(") and entry.endswith(")"):
        obj_id = entry[4:-1]
        obj = object_map.get(obj_id)
        return obj.get("name", f"OBJ({obj_id})") if obj else f"OBJ({obj_id})"
    elif entry.startswith("GRP(") and entry.endswith(")"):
        grp_id = entry[4:-1]
        group = group_map.get(grp_id)
        return group.get("name", f"GRP({grp_id})") if group else f"GRP({grp_id})"
    elif entry.lower() == "any":
        return "Any"
    return entry

def is_ip_in(search_subnet_list, rule_subnet_or_ip, inverse=False):
    try:
        rule_net = ipaddress.ip_network(rule_subnet_or_ip.strip(), strict=False)
    except ValueError:
        return False

    for search_cidr in search_subnet_list:
        try:
            search_net = ipaddress.ip_network(search_cidr.strip(), strict=False)
            if inverse:
                # Match rule if it's fully contained within the search subnet
                if rule_net.subnet_of(search_net) or rule_net == search_net:
                    return True
            else:
                # Match if search input is within the rule subnet
                if search_net.subnet_of(rule_net) or search_net == rule_net:
                    return True
        except ValueError:
            continue

    return False


def is_subnet_match(search, rule):
    """Return True if the rule subnet is fully contained in the search subnet."""
    try:
        search_net = ipaddress.ip_network(search, strict=False)
        rule_net = ipaddress.ip_network(rule, strict=False)
        return rule_net.subnet_of(search_net)
    except ValueError:
        return False

        

def match_input_to_rule(rule_cidrs, search_input):
    """True if input is in rule, or rule is in input (covers IPs, narrow or wide subnets)."""
    try:
        search_net = ipaddress.ip_network(search_input, strict=False)
    except ValueError:
        return False

    for rule_cidr in rule_cidrs:
        try:
            rule_net = ipaddress.ip_network(rule_cidr.strip(), strict=False)
            # Match if search is inside rule or rule is inside search
            if (search_net.subnet_of(rule_net)
                or rule_net.subnet_of(search_net)
                or search_net == rule_net):
                return True
        except ValueError:
            continue
    return False



def is_exact_subnet_match(input_value, rule_cidrs):
    """True if rule CIDR fully contains the input subnet or IP."""
    try:
        input_net = ipaddress.ip_network(input_value, strict=False)
    except ValueError:
        return False

    for cidr in rule_cidrs:
        try:
            rule_net = ipaddress.ip_network(cidr.strip(), strict=False)
            if input_net.prefixlen == input_net.max_prefixlen:
                if ipaddress.ip_address(input_value) in rule_net:
                    return True
            else:
                if input_net.subnet_of(rule_net):
                    return True
        except ValueError:
            continue
    return False

def resolve_to_cidrs(id_list):
    cidrs = []
    for entry in id_list:
        entry = entry.strip()
        if entry == "Any":
            cidrs.append("0.0.0.0/0")
        elif entry.startswith("OBJ(") and entry.endswith(")"):
            obj_id = entry[4:-1]
            obj = object_map.get(obj_id)
            if obj and "cidr" in obj:
                cidrs.append(obj["cidr"])
        elif entry.startswith("GRP(") and entry.endswith(")"):
            grp_id = entry[4:-1]
            group = group_map.get(grp_id)
            if group:
                for member_id in group.get("objectIds", []):
                    obj = object_map.get(str(member_id))
                    if obj and "cidr" in obj:
                        cidrs.append(obj["cidr"])
    return cidrs

# ------------------ STREAMLIT TABS ------------------
tab1, tab2, tab4 = st.tabs(["🔍 Rule Checker", "🧠 Optimization Insights",  "🔎 Object Search"])




# ------------------ RULE CHECKER TAB ------------------

with tab1:
    st.header("🔍 VPN Rule Checker")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        source_ip = st.text_input("Source IP or Subnet", "192.168.255.1")
    with col2:
        destination_ip = st.text_input("Destination IP or Subnet", "172.17.200.56")
    with col3:
        protocol = st.text_input("Protocol", "any")
    with col4:
        port_input = st.text_input("Port(s)", "443, 8080")

    filter_toggle = st.checkbox("Show only matching rules", value=False)

    skip_src_check = source_ip.strip().lower() == "any"
    skip_dst_check = destination_ip.strip().lower() == "any"
    skip_proto_check = protocol.strip().lower() == "any"
    skip_port_check = port_input.strip().lower() == "any"

    ports_to_check = [] if skip_port_check else [p.strip() for p in port_input.split(",") if p.strip().isdigit()]
    ports_to_loop = ["any"] if skip_port_check else ports_to_check

    matched_ports = {}
    rule_match_ports = {}
    found_partial_match = False
    first_exact_match_index = None

    for idx, rule in enumerate(rules_data):
        rule_protocol = rule["protocol"].lower()
        rule_ports = [p.strip() for p in rule["destPort"].split(",")] if rule["destPort"].lower() != "any" else ["any"]

        src_ids = rule["srcCidr"].split(",") if rule["srcCidr"] != "Any" else ["Any"]
        dst_ids = rule["destCidr"].split(",") if rule["destCidr"] != "Any" else ["Any"]
        resolved_src_cidrs = resolve_to_cidrs(src_ids)
        resolved_dst_cidrs = resolve_to_cidrs(dst_ids)

        src_match = True if skip_src_check else match_input_to_rule(resolved_src_cidrs, source_ip)
        dst_match = True if skip_dst_check else match_input_to_rule(resolved_dst_cidrs, destination_ip)
        proto_match = True if skip_proto_check else (rule_protocol == "any" or rule_protocol == protocol.lower())
        matched_ports_list = ports_to_loop if skip_port_check else [p for p in ports_to_loop if p in rule_ports or "any" in rule_ports]
        port_match = len(matched_ports_list) > 0

        full_match = src_match and dst_match and proto_match and port_match

        # ✅ Exact match logic (updated)
        exact_src = (
            (skip_src_check and "Any" in rule["srcCidr"]) or
            (not skip_src_check and is_exact_subnet_match(source_ip, resolved_src_cidrs))
        )
        exact_dst = (
            (skip_dst_check and "Any" in rule["destCidr"]) or
            (not skip_dst_check and is_exact_subnet_match(destination_ip, resolved_dst_cidrs))
        )
        exact_ports = skip_port_check or len(matched_ports_list) == len(ports_to_loop)
        is_exact = full_match and exact_src and exact_dst and exact_ports

        if full_match:
            rule_match_ports.setdefault(idx, []).extend(matched_ports_list)
            for port in matched_ports_list:
                if port not in matched_ports:
                    matched_ports[port] = idx

            if is_exact and not found_partial_match and first_exact_match_index is None:
                first_exact_match_index = idx
            elif not is_exact:
                found_partial_match = True

    # Build results table
    rule_rows = []
    for idx, rule in enumerate(rules_data):
        matched_ports_for_rule = rule_match_ports.get(idx, [])
        matched_any = len(matched_ports_for_rule) > 0
        is_exact_match = idx == first_exact_match_index
        is_partial_match = matched_any and not is_exact_match

        rule_rows.append({
            "Rule Index": idx,
            "Action": rule["policy"].upper(),
            "Protocol": rule["protocol"],
            "Source": ", ".join([id_to_name(x.strip()) for x in rule["srcCidr"].split(",")]),
            "Destination": ", ".join([id_to_name(x.strip()) for x in rule["destCidr"].split(",")]),
            "Ports": rule["destPort"],
            "Comment": rule.get("comment", ""),
            "Matched Ports": ", ".join(matched_ports_for_rule),
            "Matched ✅": matched_any,
            "Exact Match ✅": is_exact_match,
            "Partial Match 🔶": is_partial_match
        })

    df = pd.DataFrame(rule_rows)
    df_to_show = df[df["Matched ✅"]] if filter_toggle else df

    def highlight_row(row):
        if row["Exact Match ✅"]:
            return ['background-color: limegreen' if row["Action"] == "ALLOW" else 'background-color: crimson' for _ in row]
        elif row["Partial Match 🔶"]:
            return ['background-color: lightgreen' if row["Action"] == "ALLOW" else 'background-color: lightcoral' for _ in row]
        return ['' for _ in row]

st.dataframe(df_to_show.style.apply(highlight_row, axis=1), use_container_width=True, height=800)

#-------------------------------------------------------------------------------------------------------------------------------------
with tab2:
    st.header("🧠 Optimization Insights")

    insights = []
    seen = set()
    for i, rule in enumerate(rules_data):
        sig = (rule["policy"], rule["protocol"], rule["srcCidr"], rule["destCidr"], rule["destPort"])
        if sig in seen:
            insights.append(f"🔁 Redundant rule at index {i}: {rule.get('comment', '')}")
        else:
            seen.add(sig)

        if rule["srcCidr"] == "Any" and rule["destCidr"] == "Any" and rule["destPort"].lower() == "any":
            insights.append(f"⚠️ Broad rule at index {i} allows/denies all traffic: {rule.get('comment', '')}")

    if insights:
        for tip in insights:
            st.write(tip)
        st.download_button("📥 Download Insights", "\n".join(insights), file_name="optimization_insights.txt")
    else:
        st.success("✅ No optimization issues detected.")
        
with tab4:
    st.header("🔎 Object & Group Search")

    # 🔍 Search input
    search_term = st.text_input("Search by name:", "")

    # Filter objects and groups by search term
    if search_term:
        filtered_objs = [o for o in objects_data if search_term.lower() in o["name"].lower()]
        filtered_grps = [g for g in groups_data if search_term.lower() in g["name"].lower()]
    else:
        filtered_objs = objects_data
        filtered_grps = groups_data

    # 🔹 Matching Network Objects
    st.subheader("🔹 Matching Network Objects")
    object_rows = []
    for o in filtered_objs:
        object_rows.append({
            "ID": o.get("id", ""),
            "Name": o.get("name", ""),
            "CIDR": o.get("cidr", ""),
            "FQDN": o.get("fqdn", ""),
            "Group IDs": o.get("groupIds", []),
            "Network IDs": o.get("networkIds", [])
        })
    st.dataframe(safe_dataframe(object_rows))

# 🔸 Matching Object Groups
    st.subheader("🔸 Matching Object Groups")
    group_rows = []
    for g in filtered_grps:
        group_rows.append({
            "ID": str(g.get("id", "")),
            "Name": str(g.get("name", "")),
            "Type": str(g.get("category", "")),
            "Object Count": str(len(g.get("objectIds", []))),
            "Network IDs": ", ".join(map(str, g.get("networkIds", []))) if "networkIds" in g else ""
        })
    st.dataframe(safe_dataframe(group_rows))

    # 🔍 Group membership explorer
    if filtered_grps:
        selected_group = st.selectbox(
            "Explore group membership:",
            options=[g["id"] for g in filtered_grps],
            format_func=lambda x: group_map.get(x, {}).get("name", f"(unknown: {x})")
        )

        if selected_group and selected_group in group_map:
            group_members = group_map[selected_group].get("objectIds", [])
            member_objs = [object_map[oid] for oid in group_members if oid in object_map]

            st.markdown(f"**Group Name:** `{group_map[selected_group]['name']}`")
            st.markdown(f"**Members:** `{len(member_objs)}` object(s)`")

            member_data = []
            for o in member_objs:
                member_data.append({
                    "Object ID": o.get("id", ""),
                    "Name": o.get("name", ""),
                    "CIDR": o.get("cidr", ""),
                    "FQDN": o.get("fqdn", "")
                })

            if member_data:
                st.dataframe(safe_dataframe(member_data))
            else:
                st.info("This group has no valid or displayable objects.")
    else:
        st.info("No groups match the current search.")
