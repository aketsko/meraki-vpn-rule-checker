import streamlit as st
import pandas as pd
import requests
import json
from datetime import datetime
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
from utils.file_loader import load_json_file
from utils.helpers import safe_dataframe, get_object_map, get_group_map, id_to_name
from utils.match_logic import resolve_to_cidrs, match_input_to_rule, is_exact_subnet_match
from streamlit_searchbox import st_searchbox
#from utils.API import fetch_meraki_data_extended

# ------------------ PAGE SETUP ------------------
st.set_page_config(
    page_title="Meraki VPN Rule Checker",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

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
    </style>
""", unsafe_allow_html=True)


# ------------------ SIDEBAR FILE UPLOAD ------------------
st.sidebar.header("📡 Connect to Meraki Dashboard")

fetched_from_api = st.session_state.get("fetched_from_api", False)
with st.sidebar.expander("🔒 API Access", expanded=not (st.session_state.get("fetched_from_api") or (st.session_state.get("rules_data") and st.session_state.get("objects_data") and st.session_state.get("groups_data")))):
    
    org_id = st.text_input("🏢 Enter your Organization ID", value="")
    api_key = st.text_input("🔑 Enter your Meraki API Key", type="password")
    


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
            if not networks_resp.ok:
                raise Exception(f"Failed to fetch networks: {networks_resp.text}")
            networks = networks_resp.json()

        network_map = {net["name"]: net["id"] for net in networks}
        extended_data = {}

        progress_bar = st.progress(0)
        total = len(networks)

        for i, net in enumerate(networks, start=1):
            network_id = net["id"]
            network_name = net["name"]

            if update_progress:
                update_progress(i, len(networks), network_name)


            # Update spinner or text
            if st.session_state.get("cancel_extended_fetch"):
                raise Exception("Fetch cancelled by user.")
            # Step 1: VPN site-to-site settings
            vpn_url = f"{base_url}/networks/{network_id}/appliance/vpn/siteToSiteVpn"
            vpn_resp = requests.get(vpn_url, headers=headers)
            vpn_data = vpn_resp.json() if vpn_resp.ok else {}

            # Step 2: Organization-wide VPN firewall rules
            rules_url = f"{base_url}/organizations/{org_id}/appliance/vpn/vpnFirewallRules"
            rules_resp = requests.get(rules_url, headers=headers)
            rules_data = rules_resp.json() if rules_resp.ok else {}

            # Store results
            extended_data[network_id] = {
                "network_name": network_name,
                "vpn_settings": vpn_data,
                "vpn_rules": rules_data.get("rules", [])
            }

            progress_bar.progress((i + 1) / total)

        progress_bar.empty()
        st.success("✅ Extended Meraki data loaded.")

        return {
            "networks": networks,
            "network_map": network_map,
            "network_details": extended_data
        }

    except Exception as e:
        st.error(f"❌ Error: {e}")
        return {
            "error": str(e),
            "networks": [],
            "network_map": {},
            "network_details": {}
        }


# Try auto-fetch if session not set
if "rules_data" not in st.session_state:
    if api_key and org_id:
        rules_data, objects_data, groups_data, fetched = fetch_meraki_data(api_key, org_id)
        if fetched:
            st.session_state["rules_data"] = rules_data
            st.session_state["objects_data"] = objects_data
            st.session_state["groups_data"] = groups_data
            st.session_state["object_map"] = get_object_map(objects_data)
            st.session_state["group_map"] = get_group_map(groups_data)
            st.session_state["fetched_from_api"] = True
        else:
            st.session_state["fetched_from_api"] = False
            st.warning("⚠️ Failed to load from API. Please upload files manually.")
            
# Manual refresh on button click
if st.sidebar.button("🔄 Refresh API Data"):
    if api_key and org_id:
        rules_data, objects_data, groups_data, fetched = fetch_meraki_data(api_key, org_id)
        if fetched:
            st.session_state["rules_data"] = rules_data
            st.session_state["objects_data"] = objects_data
            st.session_state["groups_data"] = groups_data
            st.session_state["object_map"] = get_object_map(objects_data)
            st.session_state["group_map"] = get_group_map(groups_data)
            st.session_state["fetched_from_api"] = True
            st.success("✅ Data refreshed from Meraki API.")
        else:
            st.session_state["fetched_from_api"] = False
            st.error("❌ Failed to refresh data from API.")
    else:
        st.error("❌ Please enter both API key and Org ID.")


st.sidebar.markdown("---")

# Add a placeholder for progress/cancel feedback
extended_status = st.sidebar.empty()

# Place the cancel button first to register the cancel intent early
if st.sidebar.button("❌ Cancel Fetch"):
    st.session_state["cancel_extended_fetch"] = True
    extended_status.info("⛔ Fetch cancelled by user.")

# Then check for the extended fetch button
if st.sidebar.button("📡 Get Extended API Data"):
    st.session_state["cancel_extended_fetch"] = False

    progress_text = st.sidebar.empty()

    def update_progress(current, total, name):
        progress_text.markdown(
            f"🔄 **Processing network**: `{name}` ({current}/{total})"
        )

    with st.spinner("Fetching extended Meraki data (networks, VPN settings, rules)..."):
        try:
            extended_result = fetch_meraki_data_extended(api_key, org_id, update_progress=update_progress)

            # Check for cancellation
            if st.session_state.get("cancel_extended_fetch"):
                extended_status.info("⛔ Fetch cancelled before completion.")
                st.session_state["extended_data"] = None

            elif "error" in extended_result:
                extended_status.error(f"❌ Error: {extended_result['error']}")
                st.session_state["extended_data"] = None

            else:
                st.session_state["extended_data"] = extended_result
                extended_status.success("✅ Extended data successfully retrieved.")

        except Exception as e:
            extended_status.error(f"❌ Exception: {e}")
            st.session_state["extended_data"] = None


# Upload Snapshot to restore everything
uploaded_snapshot = st.sidebar.file_uploader("📤 Load API Snapshot (.json)", type="json")
if uploaded_snapshot:
    try:
        snapshot = json.load(uploaded_snapshot)
        st.session_state["rules_data"] = snapshot.get("rules_data", [])
        st.session_state["objects_data"] = snapshot.get("objects_data", [])
        st.session_state["groups_data"] = snapshot.get("groups_data", [])
        st.session_state["object_map"] = get_object_map(st.session_state["objects_data"])
        st.session_state["group_map"] = get_group_map(st.session_state["groups_data"])
        st.session_state["extended_api_data"] = snapshot.get("extended_api_data", {})
        st.success("✅ Snapshot loaded successfully!")
    except Exception as e:
        st.error(f"❌ Failed to load snapshot: {e}")


# File override only for rules if API was used
st.sidebar.header("💾 Upload Data Files")

if st.session_state.get("fetched_from_api", False):
    uploaded_rules_file = st.sidebar.file_uploader("📄 Upload alternative Rules.json", type="json", key="rules_upload")
    if uploaded_rules_file:
        uploaded_rules_file.seek(0)
        try:
            rules_json = load_json_file(uploaded_rules_file)
            st.session_state["rules_data"] = rules_json.get("rules", [])
        except Exception as e:
            st.error(f"❌ Failed to load Rules.json: {e}")

# Full manual upload fallback

if not st.session_state.get("fetched_from_api", False):
    rules_file = st.sidebar.file_uploader("Upload Rules.json", type="json")
    objects_file = st.sidebar.file_uploader("Upload Objects.json", type="json")
    groups_file = st.sidebar.file_uploader("Upload Object Groups.json", type="json")

    if all([rules_file, objects_file, groups_file]):
        try:
            rules_file.seek(0)
            objects_file.seek(0)
            groups_file.seek(0)

            st.session_state["rules_data"] = load_json_file(rules_file).get("rules", [])
            st.session_state["objects_data"] = load_json_file(objects_file)
            st.session_state["groups_data"] = load_json_file(groups_file)
            st.session_state["object_map"] = get_object_map(st.session_state["objects_data"])
            st.session_state["group_map"] = get_group_map(st.session_state["groups_data"])
        except Exception as e:
            st.error(f"❌ Failed to load one or more files: {e}")

# Load current data from session_state into local variables
rules_data = st.session_state.get("rules_data", [])
objects_data = st.session_state.get("objects_data", [])
groups_data = st.session_state.get("groups_data", [])
object_map = st.session_state.get("object_map", {})
group_map = st.session_state.get("group_map", {})

# ------------------ SIDEBAR TOOLBOX ------------------

# 🧰 Toolbox inside a collapsible section
with st.sidebar.expander("🎨 Rule Highlighting Colors", expanded=False):
    st.markdown("Adjust the colors used to highlight rule matches:")

    def color_slider(label, key, default_hex):
        return st.color_picker(label, value=st.session_state.get(key, default_hex), key=key)

    
    color_slider("Described traffic is fully ALLOWED. No rule after this one will affect the traffic. ", key="exact_allow", default_hex="#09BC8A")
    color_slider("Described traffic is partially ALLOWED. This rule can affect the traffic. To investigate further, make the search more specific. ", key="partial_allow", default_hex="#99E2B4")
    color_slider("Described traffic is fully DENIED. No rule after this one will affect the traffic.", key="exact_deny", default_hex="#DA2C38")
    color_slider("Described traffic is partially DENIED. This rule can affect the traffic. To investigate further, make the search more specific.", key="partial_deny", default_hex="#F7EF81")

# Reconstruct highlight_colors from session state
highlight_colors = {
    "exact_allow": st.session_state.get("exact_allow", "#09BC8A"),
    "exact_deny": st.session_state.get("exact_deny", "#DA2C38"),
    "partial_allow": st.session_state.get("partial_allow", "#99E2B4"),
    "partial_deny": st.session_state.get("partial_deny", "#F7EF81")
}

st.sidebar.markdown("---")

# Save & Download all API data
def prepare_snapshot():
    snapshot = {
        "rules_data": st.session_state.get("rules_data", []),
        "objects_data": st.session_state.get("objects_data", []),
        "groups_data": st.session_state.get("groups_data", []),
        "extended_api_data": st.session_state.get("extended_api_data", {})
    }
    json_str = json.dumps(snapshot, indent=2)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"meraki_snapshot_{timestamp}.json"
    return json_str, filename

# Trigger the snapshot and download immediately
if st.sidebar.button("💾 Save API Snapshot"):
    snapshot_str, snapshot_filename = prepare_snapshot()
    st.sidebar.download_button(
        label="Download Started...",
        data=snapshot_str,
        file_name=snapshot_filename,
        mime="application/json"
    )

# -------------- MANUAL TAB HANDLING ----------------
with st.container():
    col_left, col_right = st.columns([3, 5])  # Adjust width ratio as needed

    # LEFT: Label + Selectbox
    with col_left:
        st.markdown(" 🔎-🛡️-🧠 Choose the module:")
        tab_names = ["🔎 Object & Group Search", "🛡️ Rule Checker", "🧠 Optimization Insights"]

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

    # RIGHT: Metrics
    with col_right:
        col_b, col_r, col_o, col_g, col_n = st.columns(5)
        col_b.text("")
        col_r.metric("🛡️ VPN Rules", f"{len(rules_data)}")
        col_o.metric("🌐 Objects", f"{len(objects_data)}")
        col_g.metric("🗃️ Groups", f"{len(groups_data)}")
        col_n.metric("🏢 Networks", len(st.session_state.get("extended_data", {}).get("networks", [])))

# Update active_tab variable
selected_tab = st.session_state.active_tab



# -------- Render based on selected_tab ----------
if selected_tab == "🔎 Object & Group Search":

    search_term = st.text_input("Search by name or CIDR:", "").lower()

    def match_object(obj, term):
        return term in obj.get("name", "").lower() or term in obj.get("cidr", "").lower()

    filtered_objs = [o for o in objects_data if match_object(o, search_term)] if search_term else objects_data
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

elif selected_tab == "🛡️ Rule Checker":
    
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

        # --- Searchable values for protocol ---
    def search_protocol(term: str):
        options = ["any", "tcp", "udp", "icmpv4", "icmpv6"]
        term = term.strip().lower()
        return [(proto.upper(), proto) for proto in options if term in proto]

    # --- For ports: allow flexible typing, no autocomplete ---
    def passthrough_port(term: str):
        term = term.strip()
        if not term:
            return []
        return [(f"Use: {term}", term)]

    # --- Search boxes ---
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        source_input = st_searchbox(
            custom_search,
            placeholder="Source (Object, Group, CIDR, or 'any')",
            label="Source (SRC)",
            key="src_searchbox",
            default="any"
        )

    with col2:
        source_port_input = st_searchbox(
            passthrough_port,
            placeholder="e.g. 80,443 or any",
            label="Source Port(s)",
            key="srcport_searchbox",
            default="any"
        )

    with col3:
        destination_input = st_searchbox(
            custom_search,
            placeholder="Destination (Object, Group, CIDR, or 'any')",
            label="Destination (DST)",
            key="dst_searchbox",
            default="any"
        )

    with col4:
        port_input = st_searchbox(
            passthrough_port,
            placeholder="e.g. 1000-2000,443",
            label="Destination Port(s)",
            key="dstport_searchbox",
            default="any"
        )

    with col5:
        protocol = st_searchbox(
            search_protocol,
            placeholder="Protocol",
            label="Protocol",
            key="protocol_searchbox",
            default="any"
        )

    
    col_left, col_right = st.columns(2)  
    with col_right:  
        filter_toggle = st.checkbox("✅ Show only matching rules", value=False)
    
    with col_left:
        dynamic_mode = st.checkbox("🛠️ Dynymic update", value=False)
        
    if not dynamic_mode:
        st.info("Dynamic update is disabled. Switch to Dynamic update mode to evaluate.")
        st.stop()

    
    source_input = source_input or "any"
    destination_input = destination_input or "any"
    source_cidrs = resolve_search_input(source_input)
    destination_cidrs = resolve_search_input(destination_input)

    skip_src_check = source_input.strip().lower() == "any"
    skip_dst_check = destination_input.strip().lower() == "any"
    skip_proto_check = protocol.strip().lower() == "any"
    skip_dport_check = port_input.strip().lower() == "any"
    skip_sport_check = source_port_input.strip().lower() == "any"

    dports_to_check = [] if skip_dport_check else [p.strip() for p in port_input.split(",") if p.strip()]
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

        src_match = True if skip_src_check else any(match_input_to_rule(resolved_src_cidrs, cidr) for cidr in source_cidrs)
        dst_match = True if skip_dst_check else any(match_input_to_rule(resolved_dst_cidrs, cidr) for cidr in destination_cidrs)
        proto_match = True if skip_proto_check else (rule_protocol == "any" or rule_protocol == protocol.lower())

        matched_ports_list = dports_to_loop if skip_dport_check else [p for p in dports_to_loop if p in rule_dports or "any" in rule_dports]
        matched_sports_list = source_port_input.split(",") if not skip_sport_check else ["any"]
        matched_sports_list = [p.strip() for p in matched_sports_list if p in rule_sports or "any" in rule_sports]

        sport_match = len(matched_sports_list) > 0
        port_match = len(matched_ports_list) > 0 and sport_match

        full_match = src_match and dst_match and proto_match and port_match

        # Handle 'any' exact match properly
        exact_src = (
            True if skip_src_check and "0.0.0.0/0" in resolved_src_cidrs
            else all(is_exact_subnet_match(cidr, resolved_src_cidrs) for cidr in source_cidrs)
        )
        
        exact_dst = (
            True if skip_dst_check and "0.0.0.0/0" in resolved_dst_cidrs
            else all(is_exact_subnet_match(cidr, resolved_dst_cidrs) for cidr in destination_cidrs)
        )
    


        exact_ports = skip_dport_check or set(matched_ports_list) == set(dports_to_loop)
        exact_proto = skip_proto_check or rule_protocol == protocol.lower()

        is_exact = full_match and exact_src and exact_dst and exact_ports and exact_proto

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
    if (params.data["Exact Match ✅"] === true) {{
        return {{
            backgroundColor: params.data.Action === "ALLOW" ? '{highlight_colors["exact_allow"]}' : '{highlight_colors["exact_deny"]}',
            color: 'white',
            fontWeight: 'bold'
        }};
    }}
    if (params.data["Partial Match 🔶"] === true) {{
        return {{
            backgroundColor: params.data.Action === "ALLOW" ? '{highlight_colors["partial_allow"]}' : '{highlight_colors["partial_deny"]}',
            fontWeight: 'bold'
        }};
    }}
    return {{}};
}}
""")

    gb = GridOptionsBuilder.from_dataframe(df_to_show)
    gb.configure_column("Comment", wrapText=True, autoHeight=True)
    gb.configure_column("Source", wrapText=True, autoHeight=True)
    gb.configure_column("Destination", wrapText=True, autoHeight=True)
    gb.configure_column("Protocol", wrapText=True, autoHeight=True)
    gb.configure_grid_options(getRowStyle=row_style_js, domLayout='autoHeight')
    grid_options = gb.build()

    AgGrid(
        df_to_show,
        gridOptions=grid_options,
        enable_enterprise_modules=False,
        fit_columns_on_grid_load=True,
        use_container_width=True,
        allow_unsafe_jscode=True
    )

elif selected_tab == "🧠 Optimization Insights":

    def rule_covers(rule_a, rule_b):
        return (
            (rule_a["srcCidr"] == "Any" or rule_a["srcCidr"] == rule_b["srcCidr"]) and
            (rule_a["destCidr"] == "Any" or rule_a["destCidr"] == rule_b["destCidr"]) and
            (rule_a["destPort"].lower() == "any" or rule_a["destPort"] == rule_b["destPort"]) and
            (rule_a["protocol"].lower() == "any" or rule_a["protocol"] == rule_b["protocol"])
        )

    insight_rows = []
    seen_rules = set()

    for i, rule in enumerate(rules_data):
        sig = (rule["policy"], rule["protocol"], rule["srcCidr"], rule["destCidr"], rule["destPort"])
        if sig in seen_rules:
            insight_rows.append((
                f"🔁 **Duplicate Rule** at index {i + 1}: same action, protocol, source, destination, and port.",
                [i+1]
            ))
        else:
            seen_rules.add(sig)

        # Broad rule exclusion
        is_last = i == len(rules_data) - 1
        is_penultimate = i == len(rules_data) - 2
        is_allow_any = rule["policy"].lower() == "allow"
        is_deny_any = rule["policy"].lower() == "deny"

        if (rule["srcCidr"] == "Any" and rule["destCidr"] == "Any"
            and rule["destPort"].lower() == "any"
            and rule["protocol"].lower() == "any"):
            if (is_allow_any and is_last) or (is_deny_any and is_penultimate):
                pass  # expected, skip
            else:
                insight_rows.append((
                    f"⚠️ **Broad Rule Risk** at index {i+1}: `{rule['policy'].upper()} ANY to ANY on ANY` — may shadow rules below.",
                    [i+1]
                ))

        # ✅ Shadowed rule detection
        for j in range(i):
            if rule_covers(rules_data[j], rule):
                insight_rows.append((
                    f"🚫 **Shadowed Rule** at index {i+1}: unreachable due to broader rule at index {j+1}.",
                    [j+1, i+1]
                ))
                break

        # Merge opportunities
        if i < len(rules_data) - 1:
            next_rule = rules_data[i+1]
            fields_to_compare = ["policy", "srcCidr", "destCidr"]
            if all(rule[f] == next_rule[f] for f in fields_to_compare):
                if rule["destPort"] != next_rule["destPort"] and rule["protocol"] == next_rule["protocol"]:
                    insight_rows.append((
                        f"🔄 **Merge Candidate** at index {i+1} & {i+2}: same action/source/destination, different ports.",
                        [i+1, i+2]
                    ))
                elif rule["destPort"] == next_rule["destPort"] and rule["protocol"] != next_rule["protocol"]:
                    if rule["destPort"].lower() != "any" and next_rule["destPort"].lower() != "any":
                        continue
                    insight_rows.append((
                        f"🔄 **Merge Candidate** at index {i+1} & {i+2}: same action/src/dst/ports, different protocol.",
                        [i+1, i+2]
                    ))

    if insight_rows:
        for msg, rule_indexes in insight_rows:
            st.markdown(msg)
            show_rule_summary(rule_indexes)

        st.download_button("📥 Download Insights", "\n".join([msg for msg, _ in insight_rows]), file_name="optimization_insights.txt")
    else:
        st.success("✅ No optimization issues detected.")

    # ℹ️ Legend
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
