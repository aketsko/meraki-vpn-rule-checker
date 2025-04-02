import streamlit as st
from utils.file_loader import load_json_file
from utils.helpers import safe_dataframe, get_object_map, get_group_map, id_to_name
from utils.match_logic import resolve_to_cidrs, match_input_to_rule, is_exact_subnet_match
import pandas as pd

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

rules_data = load_json_file(rules_file)["rules"]
objects_data = load_json_file(objects_file)
groups_data = load_json_file(groups_file)

object_map = get_object_map(objects_data)
group_map = get_group_map(groups_data)

# ------------------ STREAMLIT TABS ------------------
tab1, tab2, tab4 = st.tabs(["🔍 Rule Checker", "🧠 Optimization Insights", "🔎 Object Search"])

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
        resolved_src_cidrs = resolve_to_cidrs(src_ids, object_map, group_map)
        resolved_dst_cidrs = resolve_to_cidrs(dst_ids, object_map, group_map)

        src_match = True if skip_src_check else match_input_to_rule(resolved_src_cidrs, source_ip)
        dst_match = True if skip_dst_check else match_input_to_rule(resolved_dst_cidrs, destination_ip)
        proto_match = True if skip_proto_check else (rule_protocol == "any" or rule_protocol == protocol.lower())
        matched_ports_list = ports_to_loop if skip_port_check else [p for p in ports_to_loop if p in rule_ports or "any" in rule_ports]
        port_match = len(matched_ports_list) > 0

        full_match = src_match and dst_match and proto_match and port_match

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
            "Source": ", ".join([id_to_name(x.strip(), object_map, group_map) for x in rule["srcCidr"].split(",")]),
            "Destination": ", ".join([id_to_name(x.strip(), object_map, group_map) for x in rule["destCidr"].split(",")]),
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