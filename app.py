import streamlit as st
import pandas as pd
import requests
import json
import ipaddress
from datetime import datetime
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
from utils.file_loader import load_json_file
from utils.helpers import safe_dataframe, get_object_map, get_group_map, id_to_name
from utils.match_logic import resolve_to_cidrs, match_input_to_rule, is_exact_subnet_match, resolve_to_cidrs_supernet_aware, find_object_locations, build_object_location_map
from streamlit_searchbox import st_searchbox
#from utils.API import fetch_meraki_data_extended

# ------------------ PAGE SETUP ------------------
st.set_page_config(
    page_title="Meraki Network Toolkit",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)
# Define default_colours with some example values
default_colours = {
    "exact_allow": "#09BC8A",
    "exact_deny": "#DA2C38",
    "partial_allow": "#99E2B4",
    "partial_deny": "#F7EF81"
}

for k, v in default_colours.items():
    st.session_state.setdefault(k, v)

def load_json_file(uploaded_file):
    try:
        if uploaded_file is None:
            raise ValueError("No file provided")

        content = uploaded_file.read()
        if not content:
            raise ValueError("Uploaded file is empty")

        if isinstance(content, bytes):
            content = content.decode("utf-8")

        content = content.strip()
        if not content:
            raise ValueError("Uploaded file contains no data")

        return json.loads(content)

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")
    except Exception as e:
        raise ValueError(f"Error reading uploaded file: {e}")
def search_objects_and_groups(searchterm: str):
    results = []

    for obj in objects_data:
        if searchterm.lower() in obj.get("name", "").lower() or searchterm in obj.get("cidr", ""):
            results.append((f"{obj['name']} ({obj.get('cidr', '')})", obj["name"]))

    for group in groups_data:
        if searchterm.lower() in group.get("name", "").lower():
            results.append((f"{group['name']} (Group)", group["name"]))

    return results


def resolve_search_input(input_str):
    if not input_str or str(input_str).strip().lower() == "any":
        return ["0.0.0.0/0"]
    input_str = input_str.strip()
    for obj in objects_data:
        if input_str == obj["name"]:
            return [obj["cidr"]]
    for group in groups_data:
        if input_str == group["name"]:
            return [object_map[obj_id]["cidr"] for obj_id in group["objectIds"] if obj_id in object_map and "cidr" in object_map[obj_id]]
    return [input_str]


def show_rule_summary(indexes):
    rows = []
    for i in indexes:
        if 1 <= i <= len(rules_data):
            r = rules_data[i - 1]  # Convert 1-based to 0-based
            rows.append({
                "Index": i,
                "Action": r["policy"].upper(),
                "Protocol": r["protocol"],
                "Src": r["srcCidr"],
                "Dst": r["destCidr"],
                "DPort": r["destPort"],
                "Comment": r.get("comment", "")
            })
        else:
            st.warning(f"⚠️ Skipping invalid rule index: {i}")
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

st.markdown("""
<style>
/* Force main container to always use full width */
.css-18e3th9 {
    flex: 1 1 100%;
    max-width: 50%;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
    <style>
    /* Sidebar file uploader text color */
    section[data-testid="stSidebar"] .stFileUploader label,
    section[data-testid="stSidebar"] .stFileUploader span {
        color: black !important;
    }
    .stButton > button {
        width: 100%;
    }
    /* More reliable targeting of expander headers */
    details > summary {
        font-size: 20px !important;
        font-weight: bold;
    }

    /* Optional: spacing and padding adjustments */
    summary {
        padding: 4px;
        margin-bottom: 4px;
    }
    </style>
""", unsafe_allow_html=True)

def generate_rule_table(rules, 
    source_port_input,
    port_input,
    protocol,
    filter_toggle,
    object_map,
    group_map,
    highlight_colors,
    source_cidrs,
    destination_cidrs,
    skip_src_check,
    skip_dst_check,
    title_prefix="Rules",
    key="default_grid"
):
    rule_rows = []
    rule_match_ports = {}
    matched_ports = {}
    found_partial_match = False
    first_exact_match_index = None

    for idx, rule in enumerate(rules):
        rule_protocol = rule["protocol"].lower()
        rule_dports = [p.strip() for p in rule["destPort"].split(",")] if rule["destPort"].lower() != "any" else ["any"]
        rule_sports = [p.strip() for p in rule.get("srcPort", "").split(",")] if rule.get("srcPort", "").lower() != "any" else ["any"]

        src_ids = rule["srcCidr"].split(",") if rule["srcCidr"] != "Any" else ["Any"]
        dst_ids = rule["destCidr"].split(",") if rule["destCidr"] != "Any" else ["Any"]
        resolved_src_cidrs = resolve_to_cidrs_supernet_aware(src_ids, object_map, group_map)
        resolved_dst_cidrs = resolve_to_cidrs_supernet_aware(dst_ids, object_map, group_map)

        src_match = True if skip_src_check else any(match_input_to_rule(resolved_src_cidrs, cidr) for cidr in source_cidrs)
        dst_match = True if skip_dst_check else any(match_input_to_rule(resolved_dst_cidrs, cidr) for cidr in destination_cidrs)

        skip_proto_check = protocol.strip().lower() == "any"
        if skip_proto_check:
            # "any" input should match all protocols
            proto_match = True
            exact_proto = rule_protocol == "any"
        else:
            proto_match = rule_protocol == protocol.lower() or rule_protocol == "any"
            exact_proto = rule_protocol == protocol.lower()

        dports_to_loop = port_input.split(",") if port_input.strip().lower() != "any" else ["any"]
        skip_dport_check = port_input.strip().lower() == "any"
        matched_ports_list = dports_to_loop if skip_dport_check else [p for p in dports_to_loop if p in rule_dports or "any" in rule_dports]

        skip_sport_check = source_port_input.strip().lower() == "any"
        src_ports_input_list = source_port_input.split(",") if not skip_sport_check else ["any"]
        matched_sports_list = [p.strip() for p in src_ports_input_list if p.strip() in rule_sports or "any" in rule_sports]

        sport_match = True if skip_sport_check else len(matched_sports_list) > 0
        port_match = True if skip_dport_check else len(matched_ports_list) > 0

        # Combine both port match checks
        port_match = port_match and sport_match
        full_match = src_match and dst_match and proto_match and port_match

        exact_src = (
            True if skip_src_check and "0.0.0.0/0" in resolved_src_cidrs
            else all(is_exact_subnet_match(cidr, resolved_src_cidrs) for cidr in source_cidrs)
        )
        exact_dst = (
            True if skip_dst_check and "0.0.0.0/0" in resolved_dst_cidrs
            else all(is_exact_subnet_match(cidr, resolved_dst_cidrs) for cidr in destination_cidrs)
        )

        input_dports_set = set(p.strip() for p in dports_to_loop if p.strip())
        rule_dports_set = set(rule_dports)
        exact_ports = (rule_dports_set == {"any"}) if skip_dport_check else (rule_dports_set == input_dports_set)


        input_sports_set = set(p.strip() for p in src_ports_input_list if p.strip())
        rule_sports_set = set(rule_sports)
        exact_sports = (rule_sports_set == {"any"}) if skip_sport_check else (rule_sports_set == input_sports_set)

        is_exact = full_match and exact_src and exact_dst and exact_ports and exact_sports and exact_proto
        #if full_match:
        #    st.write(f"[DEBUG] Rule #{idx+1} Full Match ✅ | exact_src: {exact_src}, exact_dst: {exact_dst}, exact_ports: {exact_ports}, exact_sports: {exact_sports}, exact_proto: {exact_proto}")

        if full_match:
            rule_match_ports.setdefault(idx, []).extend(matched_ports_list)
            for port in matched_ports_list:
                if port not in matched_ports:
                    matched_ports[port] = idx
            if is_exact and first_exact_match_index is None:
                first_exact_match_index = idx
            # elif not is_exact:
            #     found_partial_match = True

    for idx, rule in enumerate(rules):
        matched_ports_for_rule = rule_match_ports.get(idx, [])
        matched_any = len(matched_ports_for_rule) > 0
        is_exact_match = idx == first_exact_match_index
        is_partial_match = matched_any and not is_exact_match

        source_names = [id_to_name(cidr.strip(), object_map, group_map) for cidr in rule["srcCidr"].split(",")]
        dest_names = [id_to_name(cidr.strip(), object_map, group_map) for cidr in rule["destCidr"].split(",")]

        rule_rows.append({
            "Rule Index": idx + 1,
            "Action": rule["policy"].upper(),
            "Comment": rule.get("comment", ""),
            "Source": ", ".join(source_names),
            "Source Port": rule.get("srcPort", ""),
            "Destination": ", ".join(dest_names),
            "Ports": rule["destPort"],
            "Protocol": rule["protocol"],
            "Matched Ports": ", ".join(matched_ports_for_rule),
            "Matched ✅": matched_any,
            "Exact Match ✅": is_exact_match,
            "Partial Match 🔶": is_partial_match
        })

    df = pd.DataFrame(rule_rows)
    df_to_show = df[df["Matched ✅"]] if filter_toggle else df

   
    row_style_js = JsCode(f"""
    function(params) {{
        const isExact = params.data['Exact Match ✅'];
        const isPartial = params.data['Partial Match 🔶'];
        const action = params.data['Action'];

        if (isExact) {{
            return {{
                backgroundColor: action === "ALLOW" ? '{highlight_colors["exact_allow"]}' : '{highlight_colors["exact_deny"]}',
                color: 'white',
                fontWeight: 'bold'
            }};
        }}
        if (isPartial) {{
            return {{
                backgroundColor: action === "ALLOW" ? '{highlight_colors["partial_allow"]}' : '{highlight_colors["partial_deny"]}',
                fontWeight: 'bold'
            }};
        }}
        return {{}};
    }}
    """)


    gb = GridOptionsBuilder.from_dataframe(df_to_show) # Initialize GridOptionsBuilder with a DataFrame
    # Configure specific columns to be wider
    gb.configure_column("Comment", flex=3, minWidth=200, wrapText=True, autoHeight=True)
    gb.configure_column("Source", flex=3, minWidth=200, wrapText=True, autoHeight=True)
    gb.configure_column("Destination", flex=3, minWidth=200, wrapText=True, autoHeight=True)
    gb.configure_grid_options(getRowStyle=row_style_js, domLayout='autoHeight')
    grid_options = gb.build()

    st.markdown(title_prefix)
#    st.dataframe(df_to_show)
    AgGrid(
        df_to_show,
        gridOptions=grid_options,
        enable_enterprise_modules=False,
        fit_columns_on_grid_load=True,
        use_container_width=True,
        allow_unsafe_jscode=True,
        key=key
    )

# ------------------ API CONFIG ------------------
def get_api_headers(api_key, org_id):
    return {
        "X-Cisco-Meraki-API-Key": api_key,
        "Content-Type": "application/json",
        "X-Cisco-Meraki-Organization-ID": org_id
    }

def fetch_meraki_data(api_key, org_id):
    try:
        headers = get_api_headers(api_key, org_id)
        rules_url = f"https://api.meraki.com/api/v1/organizations/{org_id}/appliance/vpn/vpnFirewallRules"
        objects_url = f"https://api.meraki.com/api/v1/organizations/{org_id}/policyObjects"
        groups_url = f"https://api.meraki.com/api/v1/organizations/{org_id}/policyObjects/groups"

        rules_resp = requests.get(rules_url, headers=headers)
        objects_resp = requests.get(objects_url, headers=headers)
        groups_resp = requests.get(groups_url, headers=headers)

        if rules_resp.ok and objects_resp.ok and groups_resp.ok:
            return (
                rules_resp.json().get("rules", []),
                objects_resp.json(),
                groups_resp.json(),
                True
            )
        else:
            return [], [], [], False
    except Exception as e:
        st.warning(f"API fetch error: {e}")
        return [], [], [], False


def fetch_meraki_data_extended(api_key: str, org_id: str, update_progress=None, base_url="https://api.meraki.com/api/v1"):
    headers = {
        "X-Cisco-Meraki-API-Key": api_key,
        "Content-Type": "application/json",
    }

    try:
        with st.spinner("🔄 Fetching network list..."):
            networks_url = f"{base_url}/organizations/{org_id}/networks"
            networks_resp = requests.get(networks_url, headers=headers)
            networks = networks_resp.json() if networks_resp.ok else []
            if not networks:
                raise Exception("No networks retrieved")

        network_map = {net["name"]: net["id"] for net in networks}
        extended_data = {}
        location_map = {}

        progress_bar = st.progress(0)
        total = len(networks)

        for i, net in enumerate(networks, start=1):
            if update_progress:
                update_progress(i, total, net["name"])
            if st.session_state.get("cancel_extended_fetch"):
                raise Exception("Fetch cancelled by user.")

            network_id = net["id"]
            network_name = net["name"]

            vpn_url = f"{base_url}/networks/{network_id}/appliance/vpn/siteToSiteVpn"
            rules_url = f"{base_url}/networks/{network_id}/appliance/firewall/l3FirewallRules"
            vlan_url = f"{base_url}/networks/{network_id}/appliance/vlans"
            static_url = f"{base_url}/networks/{network_id}/appliance/staticRoutes"

            vpn_resp = requests.get(vpn_url, headers=headers)
            rules_resp = requests.get(rules_url, headers=headers)
            vlan_resp = requests.get(vlan_url, headers=headers)
            static_resp = requests.get(static_url, headers=headers)

            vpn_data = vpn_resp.json() if vpn_resp.ok else {}
            rules_data = rules_resp.json() if rules_resp.ok else {}
            vlan_data = vlan_resp.json() if vlan_resp.ok else []
            static_data = static_resp.json() if static_resp.ok else []

            subnets = vpn_data.get("subnets", [])
            for s in subnets:
                s["metadata"] = []
                subnet_cidr = s.get("localSubnet")
                if not subnet_cidr:
                    continue
                try:
                    target = ipaddress.ip_network(subnet_cidr, strict=False)
                except:
                    continue

                for vlan in vlan_data:
                    vlan_cidr = vlan.get("subnet")
                    if vlan_cidr:
                        try:
                            net = ipaddress.ip_network(vlan_cidr, strict=False)
                            if net == target:
                                s["metadata"].append({
                                    "name": vlan.get("name", "Unnamed VLAN"),
                                    "type": "vlan"
                                })
                        except:
                            continue

                for route in static_data:
                    route_cidr = route.get("subnet")
                    if route_cidr:
                        try:
                            net = ipaddress.ip_network(route_cidr, strict=False)
                            if net == target:
                                s["metadata"].append({
                                    "name": route.get("name", "Unnamed Route"),
                                    "type": "staticRoute"
                                })
                        except:
                            continue

            extended_data[network_id] = {
                "network_name": network_name,
                "vpn_settings": vpn_data,
                "firewall_rules": rules_data.get("rules", [])
            }

        # Rebuild location mapping based on resolved subnets
        obj_map = st.session_state.get("object_map", {})
        grp_map = st.session_state.get("group_map", {})

        for network_id, data in extended_data.items():
            subnets = [s.get("localSubnet") for s in data.get("vpn_settings", {}).get("subnets", []) if "localSubnet" in s]
            network_name = data.get("network_name")

            for obj_id, obj in obj_map.items():
                if "cidr" in obj:
                    try:
                        ip = ipaddress.ip_network(obj["cidr"], strict=False)
                        for subnet in subnets:
                            net = ipaddress.ip_network(subnet, strict=False)
                            if ip.subnet_of(net) or ip == net:
                                location_map.setdefault(f"OBJ({obj_id})", []).append(network_name)
                    except:
                        continue

            for grp_id, group in grp_map.items():
                members = group.get("objectIds", [])
                for m in members:
                    member_obj = obj_map.get(m)
                    if member_obj and "cidr" in member_obj:
                        try:
                            ip = ipaddress.ip_network(member_obj["cidr"], strict=False)
                            for subnet in subnets:
                                net = ipaddress.ip_network(subnet, strict=False)
                                if ip.subnet_of(net) or ip == net:
                                    location_map.setdefault(f"GRP({grp_id})", []).append(network_name)
                        except:
                            continue

        progress_bar.empty()
        return {
            "networks": networks,
            "network_map": network_map,
            "network_details": extended_data,
            "location_map": location_map
        }

    except Exception as e:
        st.error(f"❌ Error: {e}")
        return {
            "error": str(e),
            "networks": [],
            "network_map": {},
            "network_details": {},
            "location_map": {}
        }


def save_snapshot(data, object_location_map, extended_data):
    snapshot = {
        "raw_data": data,
        "object_location_map": object_location_map,
        "extended_api_data": extended_data,
    }
    return snapshot

def load_snapshot(snapshot):
    raw_data = snapshot.get("raw_data", {})
    object_location_map = snapshot.get("object_location_map", {})
    extended_data = snapshot.get("extended_api_data", {})
    return raw_data, object_location_map, extended_data



def prepare_snapshot(rules_data, objects_data, groups_data, extended_data, object_location_map):
    snapshot = {
        "rules_data": rules_data,
        "objects_data": objects_data,
        "groups_data": groups_data,
        "extended_api_data": extended_data or {},
        "location_map": object_location_map or {}
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"meraki_snapshot_{timestamp}.json"

    return json.dumps(snapshot, indent=2), filename


st.sidebar.header("☰ Menu")
st.session_state["api_data_expander"] = False
collapse_expanders = bool(st.session_state.get("extended_data") or st.session_state.get("rules_data") or st.session_state["api_data_expander"])

st.sidebar.markdown("📦 Load Meraki Dashboard Data")
with st.sidebar.expander("🔽 Fetch Data", expanded=not collapse_expanders):

    org_id = st.text_input("🆔 Enter your Organization ID", value="")
    api_key = st.text_input("🔑 Enter your Meraki API Key", type="password")

    if st.button("☁️ Fetch Data from API"):
        if not api_key or not org_id:
            st.error("❌ Please enter both API key and Org ID.")
        else:
            with st.spinner("🔄 Fetching all API data..."):
                try:
                    # --- Step 1: Fetch basic data ---
                    rules_data, objects_data, groups_data, fetched = fetch_meraki_data(api_key, org_id)
                    if not fetched:
                        st.session_state["fetched_from_api"] = False
                        st.error("❌ Failed to refresh base data from API.")
                    else:
                        st.session_state["rules_data"] = rules_data
                        st.session_state["objects_data"] = objects_data
                        st.session_state["groups_data"] = groups_data
                        st.session_state["object_map"] = get_object_map(objects_data)
                        st.session_state["group_map"] = get_group_map(groups_data)
                        st.session_state["fetched_from_api"] = True

                        # --- Step 2: Fetch extended data ---
                        st.session_state["cancel_extended_fetch"] = False
                        st.session_state["fetching_extended"] = True

                        progress_bar = st.progress(0)
                        progress_text = st.empty()

                        def update_progress(current, total, name):
                            ratio = current / total if total else 0
                            ratio = min(max(ratio, 0.0), 1.0)
                            try:
                                progress_bar.progress(ratio)
                                progress_text.markdown(
                                    f"🔄 **Processing network**: ({current}/{total})<br>`{name}`",
                                    unsafe_allow_html=True
                                )
                            except:
                                pass

                        try:
                            extended_result = fetch_meraki_data_extended(api_key, org_id, update_progress=update_progress)
                            if st.session_state.get("cancel_extended_fetch"):
                                st.info("⛔ Fetch cancelled before completion.")
                                st.session_state["extended_data"] = None
                                st.session_state["object_location_map"] = {}
                            elif "error" in extended_result:
                                st.error(f"❌ Error: {extended_result['error']}")
                                st.session_state["extended_data"] = None
                                st.session_state["object_location_map"] = {}
                            else:
                                st.session_state["extended_data"] = extended_result
                                st.success("✅ Extended Meraki data fetched successfully.")

                                with st.spinner("🧠 Mapping objects to VPN locations..."):
                                    location_map = build_object_location_map(
                                        st.session_state["objects_data"],
                                        st.session_state["groups_data"],
                                        extended_result
                                    )
                                    st.session_state["object_location_map"] = location_map

                        except Exception as e:
                            st.error(f"❌ Exception during extended data fetch: {e}")
                            st.session_state["extended_data"] = None
                            st.session_state["object_location_map"] = {}

                        st.session_state["fetching_extended"] = False
                        progress_bar.empty()
                        progress_text.empty()

                except Exception as e:
                    st.error(f"❌ Exception during data fetch: {e}")
                    st.session_state["fetched_from_api"] = False


    # Upload Snapshot to restore everything
    uploaded_snapshot = st.file_uploader("📤 Load Snapshot (.json)", type="json")
    if uploaded_snapshot:
        try:
            snapshot = json.load(uploaded_snapshot)

            st.session_state["rules_data"] = snapshot.get("rules_data", [])
            st.session_state["objects_data"] = snapshot.get("objects_data", [])
            st.session_state["groups_data"] = snapshot.get("groups_data", [])
            st.session_state["object_map"] = get_object_map(st.session_state["objects_data"])
            st.session_state["group_map"] = get_group_map(st.session_state["groups_data"])
            st.session_state["extended_data"] = snapshot.get("extended_api_data", {})
            st.session_state["object_location_map"] = snapshot.get("location_map", {})  
            st.session_state["fetched_from_api"] = True  # Emulate success

            network_count = len(st.session_state["extended_data"].get("network_map", {}))
            snapshot_msg = st.empty()
            snapshot_msg.success(f"📤 Snapshot loaded. Networks: {network_count}, Rules: {len(st.session_state['rules_data'])}")
            snapshot_msg.empty()

        except Exception as e:
            st.error(f"❌ Failed to load snapshot: {e}")


    # Update local variables from session
    rules_data = st.session_state.get("rules_data", [])
    objects_data = st.session_state.get("objects_data", [])
    groups_data = st.session_state.get("groups_data", [])
    object_map = st.session_state.get("object_map", {})
    group_map = st.session_state.get("group_map", {})

    

    # Snapshot creation + download
    if st.button("💾 Create Data Snapshot"):
        st.session_state["snapshot_expander_open"] = True
        try:
            snapshot_str, snapshot_filename = prepare_snapshot(
                st.session_state.get("rules_data", []),
                st.session_state.get("objects_data", []),
                st.session_state.get("groups_data", []),
                st.session_state.get("extended_data", {}),
                st.session_state.get("object_location_map", {})
            )

            st.download_button(
                label="📥 Download API Snapshot",
                data=snapshot_str,
                file_name=snapshot_filename,
                mime="application/json",
                key="auto_snapshot_download"
            )
        except Exception as e:
            st.error(f"❌ Snapshot error: {e}")



# -------------- MANUAL TAB HANDLING ----------------
with st.container():
    col_left, col_right = st.columns([3, 5])  # Adjust width ratio as needed

    # LEFT: Label + Selectbox
    with col_left:
        st.markdown(" 📘-🔎-🛡️-🧠 Choose the module:")
        tab_names = ["📘 Overview", "🔎 Search Object or Group", "🛡️ Search in Firewall and VPN Rules", "🧠 Optimization Insights"]

        if "active_tab" not in st.session_state:
            st.session_state.active_tab = tab_names[0]  # Default

        def on_tab_change():
            st.session_state.active_tab = st.session_state["selected_tab"]

        st.selectbox(
            "Select Tab",
            tab_names,
            index=tab_names.index(st.session_state.active_tab),
            key="selected_tab",
            on_change=on_tab_change,
            label_visibility="collapsed"
        )

    # Detect tab switch and collapse expanders if not on startup tab
    if "last_active_tab" not in st.session_state:
        st.session_state.last_active_tab = st.session_state.active_tab

    # When user changes tab, collapse API/Data expanders
    if st.session_state.active_tab != st.session_state.last_active_tab:
        if st.session_state.active_tab != "☁️ API & Snapshot":
            st.session_state["api_data_expander"] = False
        st.session_state.last_active_tab = st.session_state.active_tab


    # RIGHT: Metrics
    with col_right:
        col_b, col_n, col_o, col_g, col_r = st.columns(5)
        col_b.text("")
        col_r.metric("🛡️ VPN Rules", f"{len(rules_data)}")
        col_o.metric("🌐 Objects", f"{len(objects_data)}")
        col_g.metric("🗃️ Groups", f"{len(groups_data)}")
        network_count = len(st.session_state.get("extended_data", {}).get("network_map", {}))
        col_n.metric("🏢 Networks", network_count)


# Update active_tab variable
selected_tab = st.session_state.active_tab


if selected_tab == "📘 Overview":
    data_loaded = (
        st.session_state.get("rules_data")
        and st.session_state.get("objects_data")
        and st.session_state.get("extended_data")
    )

    if not data_loaded:
        with st.expander("📘 Introduction", expanded=True):
            st.markdown("""
            ## Welcome to the Meraki Network Toolkit

            This app helps you analyze and understand Meraki firewall and VPN configurations.
            
            ### Tabs Overview:
            - 🔎 **Search Object or Group**: Browse and filter network objects/groups and view their metadata and location.
            - 🛡️ **Firewall & VPN Rules**: Check how specific traffic is handled based on source, destination, ports, and protocol.
            - 🧠 **Optimization Insights**: Get tips on improving your rulebase (e.g., shadowed, duplicate, or broad rules).
            
            👉 **Start by connecting to Meraki or uploading your JSON snapshot in the sidebar.**
            """)
    else:

        with st.expander("📘 About this tab (click to collapse)", expanded=False):
            st.markdown("""
            Use this section to explore how your networks are configured in terms of VPN settings and subnets.
            
            - You can pick a network from the dropdown.
            - It shows its VPN subnets.
            - You'll see if each subnet is part of the `useVpn` list.
            - Matching objects (exact CIDR match) will be listed.
            """)

        
        extended_data = st.session_state["extended_data"]
        objects_data = st.session_state["objects_data"]
        network_map = extended_data.get("network_map", {})
        network_details = extended_data.get("network_details", {})
        network_names = sorted([v["network_name"] for v in network_details.values()])

       # selected_network = st.selectbox("🏢 Choose a Network", options=network_names)
       # Optional search for a subnet
        
        with st.sidebar:
            search_cidr = st.text_input("🔍 Search by IP or Subnet (e.g. 192.168.1.0 or 192.168.1.0/24)", "").strip()

            auto_selected_network = None
            cidr_valid = False
            cidr_matched = False

            if search_cidr:
                try:
                    # Auto-add /32 if no mask given (IP-only)
                    if "/" not in search_cidr:
                        search_cidr += "/32"
                    search_net = ipaddress.ip_network(search_cidr, strict=False)
                    cidr_valid = True

                    for nid, info in network_details.items():
                        for s in info.get("vpn_settings", {}).get("subnets", []):
                            cidr = s.get("localSubnet")
                            if cidr:
                                try:
                                    net = ipaddress.ip_network(cidr, strict=False)
                                    if search_net.subnet_of(net) or search_net == net or net.subnet_of(search_net):
                                        auto_selected_network = info.get("network_name")
                                        cidr_matched = True
                                        break
                                except:
                                    continue
                        if cidr_matched:
                            break

                except ValueError:
                    st.warning("❌ Invalid format. Example: 192.168.1.0 or 192.168.1.0/24")

            if cidr_valid and not cidr_matched:
                st.warning(f"⚠️ No matching network found for `{search_cidr}`")

            selected_network = st.selectbox(
                "🏢 Choose a Network",
                options=network_names,
                index=network_names.index(auto_selected_network) if auto_selected_network in network_names else 0
            )


        # Display table after network selected
        if selected_network:
            # Get VPN subnets and useVpn flags
            selected_net_id = None
            for nid, info in network_details.items():
                if info.get("network_name") == selected_network:
                    selected_net_id = nid
                    break

            if not selected_net_id:
                st.warning("❌ Selected network not found.")
                st.stop()

            vpn_info = network_details[selected_net_id].get("vpn_settings", {})
            vpn_subnets = vpn_info.get("subnets", [])
            use_vpn_enabled_subnets = {s["localSubnet"] for s in vpn_subnets if s.get("useVpn") is True}




            # Build rows
            rows = []
            vpn_info = network_details[selected_net_id].get("vpn_settings", {})
            vpn_subnets = vpn_info.get("subnets", [])

            for s in vpn_subnets:
                cidr = s.get("localSubnet")
                use_vpn = s.get("useVpn", False)  # This is a Python boolean
                metadata = s.get("metadata", [])
                if metadata:
                    Subnet_Name = metadata[0].get("name", "")
                    Type = metadata[0].get("type", "")
                else:
                    Subnet_Name = ""
                    Type = ""

                
                if not cidr:
                    continue

                # Find matching objects
                matched_objects = []
                try:
                    subnet_net = ipaddress.ip_network(cidr, strict=False)
                    for obj in objects_data:
                        obj_cidr = obj.get("cidr")
                        if not obj_cidr:
                            continue
                        try:
                            obj_net = ipaddress.ip_network(obj_cidr, strict=False)
                            if obj_net == subnet_net or obj_net.subnet_of(subnet_net):
                                matched_objects.append(obj["name"])
                        except:
                            continue
                except:
                    continue

                rows.append({
                    "Subnet Name": Subnet_Name,
                    "Type": Type,
                    "CIDR": cidr,
                    "In VPN": "✅" if use_vpn else "❌",
                    "Objects": ", ".join(matched_objects) if matched_objects else "—"
                })

            if rows:
                df = pd.DataFrame(rows)
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No subnets found for this network.")

            st.markdown("---")
           # st.subheader("🧱 View Local Firewall Rules by Location")

            extended_data = st.session_state.get("extended_data", {})
            network_details = extended_data.get("network_details", {}) if extended_data else {}
            network_id = extended_data.get("network_map", {}).get(selected_network, None)
            all_locations = sorted(
                info.get("network_name", "")
                for info in network_details.values()
                if info.get("firewall_rules")
            )

            if not all_locations:
                st.info("No local firewall rule data available. Please fetch extended data.")
            else:
                selected_loc = selected_network

                selected_rules = []
                for net_id, info in network_details.items():
                    if info.get("network_name") == selected_loc:
                        rules = info.get("firewall_rules", [])
                        break
                       
                if rules:
                    for rule in rules:
                        selected_rules.append({
                            "Policy": rule.get("policy", "").upper(),
                            "Protocol": rule.get("protocol", ""),
                            "Source": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in rule["srcCidr"].split(",")),
                            "Source Port": rule.get("srcPort", ""),
                            "Destination": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in rule["destCidr"].split(",")),
                            "Destination Port": rule.get("destPort", ""),
                            "Comment": rule.get("comment", ""),
                        })
                    df = pd.DataFrame(selected_rules)
                    if "comment" in df.columns:
                        df.rename(columns={"comment": "Comment"}, inplace=True)
                    gb = GridOptionsBuilder.from_dataframe(df)
                    gb.configure_default_column(filter=True, sortable=True, resizable=True, wrapText=True, autoHeight=True)
                    gb.configure_grid_options(domLayout="autoHeight")
                    grid_options = gb.build()

                    row_style_js = JsCode("""
                    function(params) {
                        if (params.data.Policy === "allow" || params.data.Policy === "ALLOW") {
                            return {
                                backgroundColor: '#99E2B4',
                                color: '#155724',
                                fontWeight: 'bold'
                            };
                        }
                        if (params.data.Policy === "deny" || params.data.Policy === "DENY") {
                            return {
                                backgroundColor: '#F7EF81',
                                color: '#721c24',
                                fontWeight: 'bold'
                            };
                        }
                        return {};
                    }
                    """)


                    gb = GridOptionsBuilder.from_dataframe(df)
                    gb.configure_default_column(filter=True, sortable=True, resizable=True, wrapText=True, autoHeight=True)
                    gb.configure_grid_options(getRowStyle=row_style_js, domLayout="autoHeight")
                    grid_options = gb.build()

                    st.markdown(f"📄 Showing **{len(selected_rules)}** rules for `{selected_loc}` - {network_id}")
                    AgGrid(
                        df,
                        gridOptions=grid_options,
                        enable_enterprise_modules=False,
                        fit_columns_on_grid_load=True,
                        use_container_width=True,
                        allow_unsafe_jscode=True,
                        key="overview_local_fw_table"
                    )
                else:
                    st.warning("No firewall rules found for this location.")

elif selected_tab == "🔎 Search Object or Group":

    from utils.match_logic import build_object_location_map  # Ensure this is imported

    # Build location map if extended data and not already available
    if "object_location_map" not in st.session_state and "extended_data" in st.session_state and st.session_state["extended_data"]:
        with st.spinner("🧠 Mapping objects to VPN locations..."):
            st.session_state["object_location_map"] = build_object_location_map(
                st.session_state["objects_data"],
                st.session_state["groups_data"],
                st.session_state["extended_data"]
            )

    location_map = st.session_state.get("object_location_map", {})

    # --- Sidebar Controls ---
    with st.sidebar:
        #st.markdown("### 📍 Location Filters")
        search_term = st.text_input("Search by name or CIDR:", "").lower()

        location_term = None
        if location_map:
            def location_search(term: str):
                term = term.strip().lower()
                locations = set()
                for entries in location_map.values():
                    if isinstance(entries, list):
                        for entry in entries:
                            if isinstance(entry, dict):
                                label = f"{entry.get('network', '')} (VPN)" if entry.get("useVpn") else f"{entry.get('network', '')} (Local)"
                                locations.add(label)
                return [(loc, loc) for loc in sorted(locations) if term in loc.lower()]

            location_term = st_searchbox(
                location_search,
                placeholder="🔍 Filter by location (optional)",
                label="VPN Location",
                key="location_searchbox"
            )

    def match_object(obj, term):
        return term in obj.get("name", "").lower() or term in obj.get("cidr", "").lower()

    filtered_objs = [o for o in objects_data if match_object(o, search_term)] if search_term else objects_data
    filtered_grps = [g for g in groups_data if search_term.lower() in g["name"].lower()] if search_term else groups_data

    if location_term:
        def entry_matches_location(entries):
            for entry in entries:
                if isinstance(entry, dict):
                    label = f"{entry.get('network', '')} (VPN)" if entry.get("useVpn") else f"{entry.get('network', '')} (Local)"
                    if location_term == label:
                        return True
            return False

        def obj_matches_location(o):
            obj_id = o.get("id", "")
            cidr = o.get("cidr", "")
            return entry_matches_location(location_map.get(f"OBJ({obj_id})", [])) or entry_matches_location(location_map.get(cidr, []))

        def grp_matches_location(g):
            grp_id = g.get("id", "")
            return entry_matches_location(location_map.get(f"GRP({grp_id})", []))

        filtered_objs = [o for o in filtered_objs if obj_matches_location(o)]
        filtered_grps = [g for g in filtered_grps if grp_matches_location(g)]

    st.subheader("🔹 Matching Network Objects")
    object_rows = []
    for o in filtered_objs:
        cidr = o.get("cidr", "")
        locations = []
        for entry in location_map.get(cidr, []) + location_map.get(f"OBJ({o.get('id')})", []):
            if isinstance(entry, dict):
                label = f"{entry.get('network', '')} (VPN)" if entry.get("useVpn") else f"{entry.get('network', '')} (Local)"
                locations.append(label)
        group_names = [group_map[gid]["name"] for gid in o.get("groupIds", []) if gid in group_map]

        object_rows.append({
            "ID": o.get("id", ""),
            "Name": o.get("name", ""),
            "CIDR": cidr,
            "FQDN": o.get("fqdn", ""),
            "Group Names": ", ".join(group_names),
            "Network IDs": ", ".join(map(str, o.get("networkIds", []))),
            "Location": ", ".join(sorted(locations))
        })
    st.dataframe(safe_dataframe(object_rows))

    st.subheader("🔸 Matching Object Groups")
    group_rows = []
    for g in filtered_grps:
        group_id = str(g.get("id", ""))
        group_name = str(g.get("name", ""))
        group_objects = g.get("objectIds", [])
        group_locations = set()

        for obj_id in group_objects:
            obj = object_map.get(obj_id)
            if obj:
                cidr = obj.get("cidr", "")
                entries = location_map.get(cidr, []) + location_map.get(f"OBJ({obj.get('id')})", [])
                for entry in entries:
                    if isinstance(entry, dict):
                        label = f"{entry.get('network', '')} (VPN)" if entry.get("useVpn") else f"{entry.get('network', '')} (Local)"
                        group_locations.add(label)

        for loc_entry in location_map.get(f"GRP({group_id})", []):
            if isinstance(loc_entry, dict):
                label = f"{loc_entry.get('network', '')} (VPN)" if loc_entry.get("useVpn") else f"{loc_entry.get('network', '')} (Local)"
                group_locations.add(label)

        group_rows.append({
            "ID": group_id,
            "Name": group_name,
            "Type": str(g.get("category", "")),
            "Object Count": str(len(group_objects)),
            "Network IDs": ", ".join(map(str, g.get("networkIds", []))) if "networkIds" in g else "",
            "Location": ", ".join(sorted(group_locations)) if group_locations else ""})

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
            st.markdown(f"**Members:** `{len(member_objs)}` object(s)")

            member_data = []
            for o in member_objs:
                cidr = o.get("cidr", "")
                locations = []
                for entry in location_map.get(cidr, []) + location_map.get(f"OBJ({o.get('id')})", []):
                    if isinstance(entry, dict):
                        label = f"{entry.get('network', '')} (VPN)" if entry.get("useVpn") else f"{entry.get('network', '')} (Local)"
                        locations.append(label)
                group_names = [group_map[gid]["name"] for gid in o.get("groupIds", []) if gid in group_map]

                member_data.append({
                    "ID": o.get("id", ""),
                    "Name": o.get("name", ""),
                    "CIDR": cidr,
                    "FQDN": o.get("fqdn", ""),
                    "Group Names": ", ".join(group_names),
                    "Network IDs": ", ".join(map(str, o.get("networkIds", []))),
                    "Location": ", ".join(sorted(locations))
                })

            if member_data:
                st.dataframe(safe_dataframe(member_data))
            else:
                st.info("This group has no valid or displayable objects.")
    else:
        st.info("No groups match the current search.")


elif selected_tab == "🛡️ Search in Firewall and VPN Rules":

    def get_all_locations_for_cidrs(cidrs, location_map):
        locations = set()
        for cidr in cidrs:
            mapped = location_map.get(cidr, [])
            if isinstance(mapped, dict):
                locations.add((mapped.get("network"), mapped.get("useVpn")))
            elif isinstance(mapped, list):
                for entry in mapped:
                    if isinstance(entry, dict):
                        locations.add((entry.get("network"), entry.get("useVpn")))
        return locations

    # --- Search input helpers ---
    def custom_search(term: str):
        term = term.strip()
        results = []
        if not objects_data or not groups_data:
            return [("Data not loaded yet", "any")]
        if term.lower() == "any":
            return [("Any (all traffic)", "any")]
        for obj in objects_data:
            if term.lower() in obj["name"].lower() or term in obj.get("cidr", ""):
                results.append((f"{obj['name']} ({obj.get('cidr', '')})", obj["name"]))
        for group in groups_data:
            if term.lower() in group["name"].lower():
                results.append((f"{group['name']} (Group)", group["name"]))
        if not results:
            results.append((f"Use: {term}", term))
        return results

    def search_protocol(term: str):
        options = ["any", "tcp", "udp", "icmpv4", "icmpv6"]
        term = term.strip().lower()
        return [(proto.upper(), proto) for proto in options if term in proto]

    def passthrough_port(term: str):
        term = term.strip()
        return [(f"Use: {term}", term)] if term else []

    # --- Sidebar Controls (Tab-Specific) ---
    with st.sidebar:
        st.markdown("### ↔️ Traffic Flow")
        source_input = st_searchbox(custom_search, label="Source", placeholder="Object, Group, CIDR, or 'any'", key="src_searchbox", default="any")
        source_port_input = st_searchbox(passthrough_port, label="Source Port(s)", placeholder="e.g. 80,443", key="srcport_searchbox", default="any")
        destination_input = st_searchbox(custom_search, label="Destination", placeholder="Object, Group, CIDR, or 'any'", key="dst_searchbox", default="any")
        port_input = st_searchbox(passthrough_port, label="Destination Port(s)", placeholder="e.g. 443,1000-2000", key="dstport_searchbox", default="any")
        protocol = st_searchbox(search_protocol, label="Protocol", placeholder="any, tcp, udp...", key="protocol_searchbox", default="any")
        st.markdown("### ⚙️ View Settings")
        dynamic_mode = st.checkbox("🔄 Dynamic update", value=st.session_state.get("fw_dynamic_update", False), key="fw_dynamic_update")
        filter_toggle = st.checkbox("✅ Show only matching rules", value=st.session_state.get("fw_filter_toggle", False), key="fw_filter_toggle")
        expand_all_local = st.checkbox("🧱 Expand Local Firewall Rule sections", value=st.session_state.get("fw_expand_local", False), key="fw_expand_local")



        highlight_colors = {
            "exact_allow": st.session_state.get("exact_allow", "#09BC8A"),
            "exact_deny": st.session_state.get("exact_deny", "#DA2C38"),
            "partial_allow": st.session_state.get("partial_allow", "#99E2B4"),
            "partial_deny": st.session_state.get("partial_deny", "#F7EF81")
        }

    if not st.session_state["fw_dynamic_update"]:
        st.info("Dynamic update is disabled. Switch to Dynamic update mode to evaluate.")
        st.stop()

    from utils.match_logic import evaluate_rule_scope_from_inputs
    source_cidrs = resolve_search_input(source_input)
    destination_cidrs = resolve_search_input(destination_input)
    skip_src_check = source_input.strip().lower() == "any"
    skip_dst_check = destination_input.strip().lower() == "any"

    obj_loc_map = st.session_state.get("object_location_map", {})
    extended_data = st.session_state.get("extended_data", {})

  


    if obj_loc_map and extended_data:
        rule_scope = evaluate_rule_scope_from_inputs(source_cidrs, destination_cidrs, obj_loc_map)
        src_locs = rule_scope["src_location_map"]
        dst_locs = rule_scope["dst_location_map"]
        shared_locs = rule_scope["shared_locations"]
        show_vpn = rule_scope["vpn_needed"]
        show_local = rule_scope["local_needed"]

        # 🔍 Traffic Flow Summary (Refined Layout)
        src_cidr_list = resolve_search_input(source_input)
        dst_cidr_list = resolve_search_input(destination_input)

        src_cidr_str = ", ".join(src_cidr_list) if src_cidr_list else "any"
        dst_cidr_str = ", ".join(dst_cidr_list) if dst_cidr_list else "any"

        src_port_str = source_port_input.strip() if source_port_input.strip().lower() != "any" else "any"
        dst_port_str = port_input.strip() if port_input.strip().lower() != "any" else "any"
        proto_str = protocol.strip().upper() if protocol.strip().lower() != "any" else "ANY"

        col1, col2 = st.columns([1, 10])
        with col1:
            st.subheader("🔍 Traffic Flow")
        with col2:
            with st.expander("### Details", expanded=False):

                col1, col2, col3 = st.columns([6, 6, 1])

                def format_boxed(label, value):
                    return f"""
                    <div style="margin-bottom: 0.75rem;">
                        <span style="font-weight: 600; color: #1a237e; font-size: 1.1rem;">{label}</span><br>
                        <div style="background-color: #ecf0f1; padding: 10px 14px; border-radius: 8px; margin-top: 4px;">
                            <code style="font-size: 1.05rem;">{value}</code>
                        </div>
                    </div>
                    """


                with col1:
                    st.markdown(format_boxed("Source Object", source_input or "-"), unsafe_allow_html=True)
                    st.markdown(format_boxed("Source CIDR", src_cidr_str), unsafe_allow_html=True)
                    st.markdown(format_boxed("Source Port", src_port_str), unsafe_allow_html=True)

                with col2:
                    st.markdown(format_boxed("Destination Object", destination_input or "-"), unsafe_allow_html=True)
                    st.markdown(format_boxed("Destination CIDR", dst_cidr_str), unsafe_allow_html=True)
                    st.markdown(format_boxed("Destination Port", dst_port_str), unsafe_allow_html=True)

                with col3:
                    #st.markdown("<div style='margin-top:1.8em'></div>", unsafe_allow_html=True)
                    st.markdown(format_boxed("Protocol", proto_str), unsafe_allow_html=True)

                st.markdown("---")



        if show_local:
            st.subheader("🧱 Local Firewall Rules")
            with st.sidebar:
                location_filter_title = f"📍 Location Filter ({len(set(loc for loc, _ in shared_locs))} found)"
                all_locations = sorted(set(loc for loc, _ in shared_locs))
                st.session_state.setdefault("selected_local_locations", all_locations)

                with st.expander(location_filter_title, expanded=True):
                    if st.button("✅ Select All", key="loc_select_all"):
                        st.session_state["selected_local_locations"] = all_locations
                    if st.button("❌ Deselect All", key="loc_deselect_all"):
                        st.session_state["selected_local_locations"] = []

                st.multiselect(
                    "Pick location(s) to display:",
                    options=all_locations,
                    default=st.session_state["selected_local_locations"],
                    key="selected_local_locations"
                )
                selected_locations = st.session_state["selected_local_locations"]



            seen_locations = set()


            with st.expander(f"Collapse - `{len(selected_locations)}`", expanded=st.session_state["fw_expand_local"]):
                for location_name in all_locations:
                    if location_name not in selected_locations:
                        continue
                    if location_name in seen_locations:
                        continue
                    seen_locations.add(location_name)
                    networks = extended_data.get("network_details", {})
                    matched = next(
                        ((net_id, info) for net_id, info in networks.items() if info.get("network_name") == location_name),
                        None
                    )

                    if matched:
                        net_id, info = matched
                        rules = info.get("firewall_rules", [])
                    # for net_id, info in extended_data.get("network_details", {}).items():
                    #     if info.get("network_name") == location_name:
                    #         rules = info.get("firewall_rules", [])
                        st.markdown(f"<h5 style='margin-bottom: 0.5rem; margin-top: 0.5rem;'>🧱 {location_name}</h5>", unsafe_allow_html=True)
                        st.markdown(f"_Total rules: {len(rules)}_")
                        if rules:
   #                         with st.expander(f"Collapse - `{location_name}`", expanded=st.session_state["fw_expand_local"]):
                             generate_rule_table(
                                 rules=rules,
                                 source_port_input=source_port_input,
                                 port_input=port_input,
                                 protocol=protocol,
                                 filter_toggle=st.session_state["fw_filter_toggle"],
                                 object_map=object_map,
                                 group_map=group_map,
                                 highlight_colors=highlight_colors,
                                 source_cidrs=source_cidrs,
                                 destination_cidrs=destination_cidrs,
                                 skip_src_check=skip_src_check,
                                 skip_dst_check=skip_dst_check,
                                 key=f"local_{net_id}_{location_name}"
                             )
                        else:
                            st.warning("No rules found for this location.")

        if show_vpn:
            st.subheader("🌐 VPN Firewall Rules")
            generate_rule_table(
                rules=rules_data,
                source_port_input=source_port_input,
                port_input=port_input,
                protocol=protocol,
                filter_toggle=st.session_state["fw_filter_toggle"],
                object_map=object_map,
                group_map=group_map,
                highlight_colors=highlight_colors,
                source_cidrs=source_cidrs,
                destination_cidrs=destination_cidrs,
                skip_src_check=skip_src_check,
                skip_dst_check=skip_dst_check,
                key="vpn_table"
            )


        st.sidebar.markdown("🔘 Set Colors")
        with st.sidebar.expander("🟢 🟡 🔴", expanded=False):
            st.markdown("Adjust the colors used to highlight rule matches:")
            def color_slider(label, key, default_hex):
                return st.color_picker(label, value=st.session_state.get(key, default_hex), key=key)
            color_slider("Described traffic is fully ALLOWED. No rule after this one will affect the traffic. ", key="exact_allow", default_hex="#09BC8A")
            color_slider("Described traffic is partially ALLOWED. This rule can affect the traffic. To investigate further, make the search more specific. ", key="partial_allow", default_hex="#99E2B4")
            color_slider("Described traffic is fully DENIED. No rule after this one will affect the traffic.", key="exact_deny", default_hex="#DA2C38")
            color_slider("Described traffic is partially DENIED. This rule can affect the traffic. To investigate further, make the search more specific.", key="partial_deny", default_hex="#F7EF81")

elif selected_tab == "🧠 Optimization Insights":
    # Load from session
    extended_data = st.session_state.get("extended_data", {})
    object_map = st.session_state.get("object_map", {})
    group_map = st.session_state.get("group_map", {})

    if not extended_data:
        st.warning("Extended data not available. Please fetch Meraki data first.")
        st.stop()
    
    st.markdown("## 🌐 Optimization Insights for VPN Firewall Rules")

    vpn_rules = st.session_state.get("rules_data", [])
    vpn_insights = []
    vpn_seen = set()

    def rule_covers(rule_a, rule_b):
        return (
            (rule_a["srcCidr"] == "Any" or rule_a["srcCidr"] == rule_b["srcCidr"]) and
            (rule_a["destCidr"] == "Any" or rule_a["destCidr"] == rule_b["destCidr"]) and
            (rule_a["destPort"].lower() == "any" or rule_a["destPort"] == rule_b["destPort"]) and
            (rule_a["protocol"].lower() == "any" or rule_a["protocol"] == rule_b["protocol"])
        )

    for i, rule in enumerate(vpn_rules):
        sig = (rule["policy"], rule["protocol"], rule["srcCidr"], rule["destCidr"], rule["destPort"])
        if sig in vpn_seen:
            vpn_insights.append((
                f"🔁 **Duplicate Rule** at index {i + 1}: same action, protocol, source, destination, and port.",
                [i + 1]
            ))
        else:
            vpn_seen.add(sig)

        is_last = i == len(vpn_rules) - 1
        is_penultimate = i == len(vpn_rules) - 2
        is_allow_any = rule["policy"].lower() == "allow"
        is_deny_any = rule["policy"].lower() == "deny"

        if (rule["srcCidr"] == "Any" and rule["destCidr"] == "Any"
                and rule["destPort"].lower() == "any"
                and rule["protocol"].lower() == "any"):
            if (is_allow_any and is_last) or (is_deny_any and is_penultimate):
                pass
            else:
                vpn_insights.append((
                    f"⚠️ **Broad Rule Risk** at index {i + 1}: `{rule['policy'].upper()} ANY to ANY on ANY` — may shadow rules below.",
                    [i + 1]
                ))

        for j in range(i):
            if rule_covers(vpn_rules[j], rule):
                vpn_insights.append((
                    f"🚫 **Shadowed Rule** at index {i + 1}: unreachable due to broader rule at index {j + 1}.",
                    [j + 1, i + 1]
                ))
                break

        if i < len(vpn_rules) - 1:
            next_rule = vpn_rules[i + 1]
            fields_to_compare = ["policy", "srcCidr", "destCidr"]
            if all(rule[f] == next_rule[f] for f in fields_to_compare):
                if rule["destPort"] != next_rule["destPort"] and rule["protocol"] == next_rule["protocol"]:
                    vpn_insights.append((
                        f"🔄 **Merge Candidate** at index {i + 1} & {i + 2}: same action/source/destination, different ports.",
                        [i + 1, i + 2]
                    ))
                elif rule["destPort"] == next_rule["destPort"] and rule["protocol"] != next_rule["protocol"]:
                    if rule["destPort"].lower() != "any" and next_rule["destPort"].lower() != "any":
                        continue
                    vpn_insights.append((
                        f"🔄 **Merge Candidate** at index {i + 1} & {i + 2}: same action/src/dst/ports, different protocol.",
                        [i + 1, i + 2]
                    ))

    if vpn_insights:
        for msg, rule_indexes in vpn_insights:
            st.markdown(msg)
            for idx in rule_indexes:
                show_rule_summary([idx])
        st.download_button(
            "📥 Download VPN Rule Insights",
            "\n".join([msg for msg, _ in vpn_insights]),
            file_name="vpn_optimization_insights.txt"
        )
    else:
        st.success("✅ No optimization issues detected in VPN rules.")

    with st.sidebar:
        st.markdown("### 📍 Location Filter")

        # Build list of all available locations
        networks = extended_data.get("network_details", {})
        all_locations = sorted(set(info.get("network_name") for info in networks.values() if info.get("network_name")))

        with st.expander(f"Collapse - `{len(all_locations)}`", expanded=True):
            st.session_state.setdefault("optimization_locations", all_locations)

            if st.button("✅ Select All"):
                st.session_state["optimization_locations"] = all_locations
            if st.button("❌ Deselect All"):
                st.session_state["optimization_locations"] = []

            selected_locations = st.multiselect(
                "Choose locations to analyze:",
                options=all_locations,
                default=st.session_state["optimization_locations"],
                key="optimization_locations"
            )


            seen_locations = set()


    def rule_covers(rule_a, rule_b):
        return (
            (rule_a["srcCidr"] == "Any" or rule_a["srcCidr"] == rule_b["srcCidr"]) and
            (rule_a["destCidr"] == "Any" or rule_a["destCidr"] == rule_b["destCidr"]) and
            (rule_a["destPort"].lower() == "any" or rule_a["destPort"] == rule_b["destPort"]) and
            (rule_a["protocol"].lower() == "any" or rule_a["protocol"] == rule_b["protocol"])
        )

    for location in selected_locations:
        st.markdown(f"### 🧠 Optimization Insights for `{location}`")
        rules = []
        for net_id, info in extended_data.get("network_details", {}).items():
            if info.get("network_name") == location:
                rules = info.get("firewall_rules", [])
                break

        if not rules:
            st.info("No rules found for this location.")
            continue

        insight_rows = []
        seen_rules = set()

        for i, rule in enumerate(rules):
            sig = (rule["policy"], rule["protocol"], rule["srcCidr"], rule["destCidr"], rule["destPort"])
            if sig in seen_rules:
                insight_rows.append((
                    f"🔁 **Duplicate Rule** at index {i + 1}: same action, protocol, source, destination, and port.",
                    [i + 1]
                ))
            else:
                seen_rules.add(sig)

            is_last = i == len(rules) - 1
            is_penultimate = i == len(rules) - 2
            is_allow_any = rule["policy"].lower() == "allow"
            is_deny_any = rule["policy"].lower() == "deny"

            if (rule["srcCidr"] == "Any" and rule["destCidr"] == "Any"
                    and rule["destPort"].lower() == "any"
                    and rule["protocol"].lower() == "any"):
                if (is_allow_any and is_last) or (is_deny_any and is_penultimate):
                    pass  # skip acceptable final rules
                else:
                    insight_rows.append((
                        f"⚠️ **Broad Rule Risk** at index {i + 1}: `{rule['policy'].upper()} ANY to ANY on ANY` — may shadow rules below.",
                        [i + 1]
                    ))

            for j in range(i):
                if rule_covers(rules[j], rule):
                    insight_rows.append((
                        f"🚫 **Shadowed Rule** at index {i + 1}: unreachable due to broader rule at index {j + 1}.",
                        [j + 1, i + 1]
                    ))
                    break

            if i < len(rules) - 1:
                next_rule = rules[i + 1]
                fields_to_compare = ["policy", "srcCidr", "destCidr"]
                if all(rule[f] == next_rule[f] for f in fields_to_compare):
                    if rule["destPort"] != next_rule["destPort"] and rule["protocol"] == next_rule["protocol"]:
                        insight_rows.append((
                            f"🔄 **Merge Candidate** at index {i + 1} & {i + 2}: same action/source/destination, different ports.",
                            [i + 1, i + 2]
                        ))
                    elif rule["destPort"] == next_rule["destPort"] and rule["protocol"] != next_rule["protocol"]:
                        if rule["destPort"].lower() != "any" and next_rule["destPort"].lower() != "any":
                            continue
                        insight_rows.append((
                            f"🔄 **Merge Candidate** at index {i + 1} & {i + 2}: same action/src/dst/ports, different protocol.",
                            [i + 1, i + 2]
                        ))

        with st.expander(f"🧱 Local Rules Optimization Details – {location}", expanded=False):
            if insight_rows:
                for msg, rule_indexes in insight_rows:
                    st.markdown(msg)
                    for idx in rule_indexes:
                        show_rule_summary([idx])
                st.download_button(
                    f"📥 Download Local Rules Insights – {location}",
                    "\n".join([msg for msg, _ in insight_rows]),
                    file_name=f"local_optimization_insights_{location}.txt"
                )
            else:
                st.success(f"✅ No optimization issues detected in `{location}`.")

    st.markdown("---")
    st.subheader("ℹ️ Legend")
    st.markdown("""
| Term               | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| 🔁 **Duplicate Rule** | Rule is identical to a previous one (all fields except comment)           |
| 🔄 **Merge Candidate** | Rules could be combined (only one field differs, e.g., port)              |
| ⚠️ **Broad Rule Risk** | `ANY` rule appears early and could shadow everything below               |
| 🚫 **Shadowed Rule**   | Rule is never reached because an earlier rule already matches its traffic |
""")

