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

        source_names = [id_to_name(cidr.strip(), object_map, group_map) for cidr in rule["srcCidr"].split(",")]

        dest_names = [id_to_name(cidr.strip(), object_map, group_map) for cidr in rule["destCidr"].split(",")]

        rule_rows.append({
            "Rule Index": idx,
            "Comment": rule.get("comment", ""),
            "Source": ", ".join(source_names),
            "Source Port": rule.get("srcPort", ""),
            "Destination": ", ".join(dest_names),
            "Ports": rule["destPort"],
            "Matched Ports": ", ".join(matched_ports_for_rule),
#            "Matched ✅": matched_any,
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
from st_aggrid import JsCode
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

gb.configure_default_column(filter=True, sortable=True, resizable=True)

column_defs = [
    {"field": "Rule Index", "width": 70},
    {"field": "Action", "width": 80},
    {"field": "Protocol", "width": 80},
    {"field": "Source", "width": 400},
    {"field": "Destination", "width": 400},
    {"field": "Source Port", "width": 80},
    {"field": "Ports", "width": 80},
    {"field": "Comment", "width": 500},
    {"field": "Matched Ports", "width": 80},
    {"field": "Matched ✅", "width": 80},
    {"field": "Exact Match ✅", "width": 100},
    {"field": "Partial Match 🔶", "width": 120}
]
gb.configure_columns(column_defs)
gb.configure_column("Comment", wrapText=True, autoHeight=True)
gb.configure_column("Source", wrapText=True, autoHeight=True)
gb.configure_column("Destination", wrapText=True, autoHeight=True)
gb.configure_grid_options(getRowStyle=row_style_js, domLayout='autoHeight')
grid_options = gb.build()

AgGrid(
    df_to_show,
    gridOptions=grid_options,
        enable_enterprise_modules=False,
        fit_columns_on_grid_load=True,
        
        use_container_width=True,
        allow_unsafe_jscode=with tab2:
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
#".join(insights), file_name="optimization_insights.txt")
    else:
        st.success("✅ No optimization issues detected.")

# ------------------ TAB 4: Object Search ------------------
with tab4:
    st.header("🔎 Object & Group Search")

    search_term = st.text_input("Search by name:", "")

    filtered_objs = [o for o in objects_data if search_term.lower() in o["name"].lower()] if search_term else objects_data
    filtered_grps = [g for g in groups_data if search_term.lower() in g["name"].lower()] if search_term else groups_data

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

