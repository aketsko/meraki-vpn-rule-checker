import streamlit as st
import pandas as pd
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
from utils.file_loader import load_json_file
from utils.helpers import safe_dataframe, get_object_map, get_group_map, id_to_name
from utils.match_logic import resolve_to_cidrs, match_input_to_rule, is_exact_subnet_match

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
        source_ip = st.text_input("Source IP/Subnet (SRC)", "192.168.255.1")
    with col2:
        source_port_input = st.text_input("Source Port(s)", "any")
    with col3:
        destination_ip = st.text_input("Destination IP/Subnet (DST)", "172.17.200.56")
    with col4:
        port_input = st.text_input("Destination Port(s)", "443, 8080")

    protocol = st.selectbox("Protocol", ["any", "tcp", "udp", "icmpv4", "icmpv6"], index=0)
    filter_toggle = st.checkbox("Show only matching rules", value=False)

    skip_src_check = source_ip.strip().lower() == "any"
    skip_dst_check = destination_ip.strip().lower() == "any"
    skip_proto_check = protocol.strip().lower() == "any"
    skip_dport_check = port_input.strip().lower() == "any"
    skip_sport_check = source_port_input.strip().lower() == "any"

    dports_to_check = [] if skip_dport_check else [p.strip() for p in port_input.split(",") if p.strip().isdigit()]
    dports_to_loop = ["any"] if skip_dport_check else dports_to_check

    matched_ports = {}
    rule_match_ports = {}
    found_partial_match = False
    first_exact_match_index = None

    for idx, rule in enumerate(rules_data):
        rule_protocol = rule["protocol"].lower()
        rule_dports = [p.strip() for p in rule["destPort"].split(",")] if rule["destPort"].lower() != "any" else ["any"]
        rule_sports = [p.strip() for p in rule.get("srcPort", "").split(",")] if rule.get("srcPort", "").lower() != "any" else ["any"]

        src_ids = rule["srcCidr"].split(",") if rule["srcCidr"] != "Any" else ["Any"]
        dst_ids = rule["destCidr"].split(",") if rule["destCidr"] != "Any" else ["Any"]
        resolved_src_cidrs = resolve_to_cidrs(src_ids, object_map, group_map)
        resolved_dst_cidrs = resolve_to_cidrs(dst_ids, object_map, group_map)

        src_match = True if skip_src_check else match_input_to_rule(resolved_src_cidrs, source_ip)
        dst_match = True if skip_dst_check else match_input_to_rule(resolved_dst_cidrs, destination_ip)
        proto_match = True if skip_proto_check else (rule_protocol == "any" or rule_protocol == protocol.lower())
        matched_ports_list = dports_to_loop if skip_dport_check else [p for p in dports_to_loop if p in rule_dports or "any" in rule_dports]
        matched_sports_list = source_port_input.split(",") if not skip_sport_check else ["any"]
        matched_sports_list = [p.strip() for p in matched_sports_list if p.strip() in rule_sports or "any" in rule_sports]
        sport_match = len(matched_sports_list) > 0
        port_match = len(matched_ports_list) > 0 and sport_match

        full_match = src_match and dst_match and proto_match and port_match

        exact_src = (skip_src_check and "Any" in rule["srcCidr"]) or (not skip_src_check and is_exact_subnet_match(source_ip, resolved_src_cidrs))
        exact_dst = (skip_dst_check and "Any" in rule["destCidr"]) or (not skip_dst_check and is_exact_subnet_match(destination_ip, resolved_dst_cidrs))
        exact_ports = skip_dport_check or len(matched_ports_list) == len(dports_to_loop)
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

        source_names = []
        for cidr in rule["srcCidr"].split(","):
            cidr = cidr.strip()
            resolved = resolve_to_cidrs([cidr], object_map, group_map)
            name = id_to_name(cidr, object_map, group_map)
            if not skip_src_check and match_input_to_rule(resolved, source_ip):
                source_names.append(f"<b>{name}</b>")
            else:
                source_names.append(name)

        dest_names = []
        for cidr ".join([id_to_name(x.strip(), object_map, group_map) for x in rule["srcCidr"].split(",")]),
            "Destination": ", ".join([id_to_name(x.strip(), object_map, group_map) for x in rule["destCidr"].split(",")]),
            "Source Port": rule.get("srcPort", ""),
            "Ports": rule["destPort"],
            "Comment": rule.get("comment", ""),
            "Matched Ports": ", ".join(matched_ports_for_rule),
            "Matched ✅": matched_any,
            "Exact Match ✅": is_exact_match,
            "Partial Match 🔶": is_partial_match
        })

    df = pd.DataFrame(rule_rows)
    df_to_show = df[df["Matched ✅"]] if filter_toggle else df

    # AG Grid Styling
    row_style_js = JsCode("""
function(params) {
    if (params.data["Exact Match ✅"] === true) {
        return {
            backgroundColor: params.data.Action === "ALLOW" ? '#00cc44' : '#cc0000',
            color: 'white',
            fontWeight: 'bold'
        };
    }
    if (params.data["Partial Match 🔶"] === true) {
        return {
            backgroundColor: params.data.Action === "ALLOW" ? '#99e6b3' : '#ff9999',
            fontWeight: 'bold'
        };
    }
    return {};
}
""")

    gb = GridOptionsBuilder.from_dataframe(df_to_show)
    gb.configure_default_column(filter=True, sortable=True, resizable=True)
    gb.configure_grid_options(getRowStyle=row_style_js)

# Bold matching object/group in Source column
source_cell_style = JsCode("""
function(params) {
    const input = '""" + source_ip + """';
    if (input.toLowerCase() === 'any') return {};
    if (params.value && params.value.includes(input)) {
        return { fontWeight: 'bold' };
    }
    return {};
}
""")
gb.configure_column("Source", cellStyle=source_cell_style)

# Bold matching object/group in Destination column
dest_cell_style = JsCode("""
function(params) {
    const input = '""" + destination_ip + """';
    if (input.toLowerCase() === 'any') return {};
    if (params.value && params.value.includes(input)) {
        return { fontWeight: 'bold' };
    }
    return {};
}
""")
gb.configure_column("Destination", cellStyle=dest_cell_style)
    grid_options = gb.build()

    AgGrid(
        df_to_show,
        gridOptions=grid_options,
        enable_enterprise_modules=False,
        fit_columns_on_grid_load=True,
        height=800,
        use_container_width=True,
        allow_unsafe_jscode=True
    )
