import streamlit as st
import pandas as pd
import requests
import json
import ipaddress
import base64
import requests
import copy
import os
import re
from pathlib import Path
import altair as alt
from datetime import datetime
from PIL import Image
from st_aggrid import GridUpdateMode
import streamlit.components.v1 as components
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
#from utils.API import get_api_key
from streamlit_searchbox import st_searchbox
from streamlit_extras.customize_running import center_running


# USER_CREDENTIALS = {
    # "Systemair": "Systemair_2025",
    
# }



# if "authenticated" not in st.session_state:
    # st.session_state["authenticated"] = False

# if not st.session_state["authenticated"]:
    # logo = Image.open("Logo.png")
    
    # col0,col1,col2 = st.columns([1, 3, 1]) 
    # with col0:
        # st.markdown("")
    # with col1:
        # st.image(logo)    
    # with col2:
        # st.markdown("")
    

    # st.markdown("")
    # username = st.text_input("Username")
    # password = st.text_input("Password", type="password")
    # if st.button("Login"):
        # if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
            # st.session_state["authenticated"] = True
            # st.session_state["username"] = username
            # st.session_state["password"] = password
            # st.rerun()
        # else:
            # st.error("❌ Invalid username or password.")
    # st.stop()



# ------------------ PAGE SETUP ------------------
st.set_page_config(
    page_title="Meraki Network Toolkit",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

st.markdown('<a name="top"></a>', unsafe_allow_html=True)

query_params = st.query_params
if query_params.get("scroll_to") == ["top"]:
    st.markdown('<meta http-equiv="refresh" content="0; URL=#top_of_page">', unsafe_allow_html=True)
    st.query_params()  # Clear it after use

st.markdown("""
    <a href="#top">
    <button style='position: fixed; bottom: 20px; center: 0px; z-index: 100000;'>⬆️ Back to Top</button>
    </a>
""", unsafe_allow_html=True)

# Define default_colours with some example values
default_colours = {
    "exact_allow": "#09BC8A",
    "exact_deny": "#DA2C38",
    "partial_allow": "#99E2B4",
    "partial_deny": "#F7EF81"
}
center_running()
if "operation_mode" not in st.session_state:
    st.session_state["operation_mode"] = "Add"

if "Restore_done" not in st.session_state:
    st.session_state["Restore_done"] = False

if "extended_data" not in st.session_state:
    st.session_state["extended_data"] = {}

if "objects_data" not in st.session_state:
    st.session_state["objects_data"] = []

if "groups_data" not in st.session_state:
    st.session_state["groups_data"] = []

if "rule_log" not in st.session_state:
    st.session_state["rule_log"] = []

if "preview_tables" not in st.session_state:
    st.session_state["preview_tables"] = {}

if "rule_type" not in st.session_state:
    st.session_state["rule_type"] = "Local"

if "selected_locations" not in st.session_state:
    st.session_state["selected_locations"] = []

if "devices_data" not in st.session_state:
    st.session_state["devices_data"] = []

for k, v in default_colours.items():
    st.session_state.setdefault(k, v)
st.session_state.setdefault("Fetch_DATA_Expand", True)
st.session_state.setdefault("Fetch_DATA_Expand_COLLAPSED", False)
match_comment, match_policy = None, None
# ───────────────────────────────────────────────────────────────────────────
    
def safe_dataframe(data):
    df = pd.DataFrame(data)
    for col in df.columns:
        df[col] = df[col].apply(lambda x: ", ".join(map(str, x)) if isinstance(x, list) else str(x) if x is not None else "")
    return df

def get_object_map(objects_data):
    return {obj["id"]: obj for obj in objects_data}

def get_group_map(groups_data):
    return {grp["id"]: grp for grp in groups_data}

def id_to_name(entry, object_map, group_map):
    entry = entry.strip()
    if entry.startswith("OBJ(") and entry.endswith(")"):
        obj = object_map.get(entry[4:-1])
        return obj.get("name", entry) if obj else entry
    elif entry.startswith("GRP(") and entry.endswith(")"):
        grp = group_map.get(entry[4:-1])
        return grp.get("name", entry) if grp else entry
    elif entry.lower() == "any":
        return "Any"
    return entry


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
    import ipaddress

    results = []
    seen = set()

    for item in input_list:
        matches = []

        # Direct mapping if available
        direct = object_location_map.get(item, [])
        if isinstance(direct, list):
            matches.extend(direct)

        # Special handling for "any"
        if item == "0.0.0.0/0":
            any_match = object_location_map.get("0.0.0.0/0", [])
            if isinstance(any_match, list):
                matches.extend(any_match)

        for match in matches:
            key = (match["network"], match["useVpn"])
            if key not in seen:
                seen.add(key)
                results.append(match)
    print("DEBUG find_object_locations")
    print("Results:", results)
    print("Returning set:", {(entry["network"], entry["useVpn"]) for entry in results if isinstance(entry, dict)})
    return {(entry["network"], entry["useVpn"]) for entry in results if isinstance(entry, dict)}



def evaluate_rule_scope_from_inputs(source_cidrs, dest_cidrs, obj_location_map):
    src_locs = find_object_locations(source_cidrs, obj_location_map)
    dst_locs = find_object_locations(dest_cidrs, obj_location_map)

    src_names = {loc[0].strip() for loc in src_locs if isinstance(loc, tuple)}
    dst_names = {loc[0].strip() for loc in dst_locs if isinstance(loc, tuple)}

    shared_names = src_names & dst_names
    
    
    src_vpn_locs = {
        entry.get("network")
        for cidr in source_cidrs
        for entry in obj_location_map.get(cidr, [])
        if isinstance(entry, dict) and entry.get("useVpn")
    }
    dst_vpn_locs = {
        entry.get("network")
        for cidr in dest_cidrs
        for entry in obj_location_map.get(cidr, [])
        if isinstance(entry, dict) and entry.get("useVpn")
    }

    vpn_needed = any(
        dst != src and dst in dst_vpn_locs and src in src_vpn_locs
        for src in src_vpn_locs for dst in dst_vpn_locs
    )

    local_needed = (
        bool(shared_names)
        or (src_locs and not dst_locs)
        or (dst_locs and not src_locs)
    )

    if shared_names:
        local_rule_locations = shared_names
    elif src_locs and not dst_locs:
        local_rule_locations = src_names
    elif dst_locs and not src_locs:
        local_rule_locations = dst_names
    else:
        local_rule_locations = set()
    
    return {
        "src_location_map": src_locs,
        "dst_location_map": dst_locs,
        "shared_locations": list(shared_names),
        "vpn_needed": vpn_needed,
        "local_needed": local_needed,
        "local_rule_locations": list(local_rule_locations),
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
                # Only include known networks that are *contained within* the input
                for known in known_cidrs:
                    if known.subnet_of(input_net):
                        resolved.add(str(known))
                # Also allow exact matches
                if input_net in known_cidrs:
                    resolved.add(str(input_net))
            except ValueError:
                continue

    return list(resolved)

# Streamlit version‑agnostic rerun helper

def safe_rerun() -> None:
    """
    Trigger an immediate script re‑run on every supported Streamlit version.
    • Streamlit ≥ 1.25 exposes st.rerun()
    • Older releases still use st.experimental_rerun()
    """
    try:
        st.rerun()                 # Streamlit ≥ 1.25
    except AttributeError:
        st.experimental_rerun()    # Legacy fallback
# ───────────────────────────────────────────────────────────────────────────


def resolve_names(cidr_string, object_map, group_map):
    results = []
    for cidr in cidr_string.split(","):
        cidr = cidr.strip()
        if cidr.startswith("OBJ(") and cidr.endswith(")"):
            obj_id = cidr[4:-1]
            name = object_map.get(obj_id, {}).get("name", cidr)
            results.append(name)
        elif cidr.startswith("GRP(") and cidr.endswith(")"):
            grp_id = cidr[4:-1]
            name = group_map.get(grp_id, {}).get("name", cidr)
            results.append(name)
        else:
            results.append(cidr)
    return ", ".join(results)


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

def get_invalid_objects(objects_data):
    import ipaddress
    invalid_objects = []

    for obj in objects_data:
        cidr = obj.get("cidr", "").strip()
        name = obj.get("name", "(unnamed)")
        obj_id = obj.get("id", "")

        # Optional: allow missing CIDRs if that's valid in your context
        if not cidr:
            continue  # Assume valid if no CIDR is defined

        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if str(net.network_address) != cidr.split("/")[0]:
                invalid_objects.append({
                    "ID": obj_id,
                    "Name": name,
                    "CIDR": cidr,
                    "Reason": f"CIDR not base address. Expected {net.network_address}/{net.prefixlen}"
                })
        except ValueError as e:
            invalid_objects.append({
                "ID": obj_id,
                "Name": name,
                "CIDR": cidr,
                "Reason": f"Invalid CIDR: {e}"
            })

    return invalid_objects

def fix_object_cidr(obj_id, org_id, headers):
    url = f"https://api.meraki.com/api/v1/organizations/{org_id}/policyObjects/{obj_id}"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        st.error(f"Failed to fetch object {obj_id}: {response.text}")
        return

    obj_data = response.json()
    cidr = obj_data.get("cidr", "").strip()
    if not cidr:
        st.warning(f"Object {obj_id} has no CIDR defined.")
        return

    try:
        net = ipaddress.ip_network(cidr, strict=False)
        corrected_cidr = f"{net.network_address}/{net.prefixlen}"
        if corrected_cidr == cidr:
            st.info(f"Object {obj_id} CIDR is already correct.")
            return

        obj_data["cidr"] = corrected_cidr
        put_response = requests.put(url, headers=headers, json=obj_data)
        if put_response.status_code == 200:
            st.success(f"Object {obj_id} CIDR updated to {corrected_cidr}.")
        else:
            st.error(f"Failed to update object {obj_id}: {put_response.text}")
    except ValueError as e:
        st.error(f"Invalid CIDR for object {obj_id}: {e}")


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

def generate_rule_table(rules, location_name, 
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
        resolved_rule_srcs = resolve_to_cidrs_supernet_aware(rule.get("srcCidr", "").split(","), object_map, group_map)
        resolved_rule_dsts = resolve_to_cidrs_supernet_aware(rule.get("destCidr", "").split(","), object_map, group_map)


        def any_cidr_match(rule_cidrs, input_cidrs):
            for input_cidr in input_cidrs:
                try:
                    net_input = ipaddress.ip_network(input_cidr, strict=False)
                except ValueError:
                    continue
                for rule_cidr in rule_cidrs:
                    try:
                        net_rule = ipaddress.ip_network(rule_cidr, strict=False)
                        if net_input.subnet_of(net_rule) or net_input == net_rule:
                            return True
                    except ValueError:
                        continue
            return False

        src_match = True if skip_src_check else any_cidr_match(resolved_rule_srcs, source_cidrs)
        dst_match = True if skip_dst_check else any_cidr_match(resolved_rule_dsts, destination_cidrs)

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
            True if skip_src_check and "0.0.0.0/0" in resolved_rule_srcs
            else all(is_exact_subnet_match(cidr, resolved_rule_srcs) for cidr in source_cidrs)
        )
        exact_dst = (
            True if skip_dst_check and "0.0.0.0/0" in resolved_rule_dsts
            else all(is_exact_subnet_match(cidr, resolved_rule_dsts) for cidr in destination_cidrs)
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
    gb.configure_grid_options(rowSelection='single')
    gb.configure_selection('single')
    grid_options = gb.build()

    if title_prefix.strip().lower() != "rules":
        st.markdown(title_prefix)

#    st.dataframe(df_to_show)
    grid_response = AgGrid(
        df_to_show,
        gridOptions=grid_options,
        enable_enterprise_modules=False,
        fit_columns_on_grid_load=True,
        use_container_width=True,
        allow_unsafe_jscode=True,
        key=key,
        update_mode=GridUpdateMode.SELECTION_CHANGED,
        selection_mode="single"  # or "multiple" if you want multi-select
    )
    if "redirect_rule_data" not in st.session_state:
        st.session_state["redirect_rule_data"] = {}

    selected_rows = grid_response.get("selected_rows", [])
    if isinstance(selected_rows, pd.DataFrame):
        selected_rows = selected_rows.to_dict(orient="records")
   
    if isinstance(selected_rows, list) and selected_rows:
        selected_row = selected_rows[0]
        
        st.session_state["redirect_rule_data"] = {
            "location": location_name,
            "policy": selected_row.get("Action", "").upper(),
            "comment": selected_row.get("Comment", "")
        }
        
        st.success(f"✅ Rule {selected_row.get('Comment', '')} selected for edit.")
       
        if st.button(f"✏️ Edit Selected Rule ", {location_name}):
            if st.session_state.get("redirect_rule_data"):
                # Set target state for edit
                selected_policy = st.session_state["redirect_rule_data"]["policy"]
                selected_comment = st.session_state["redirect_rule_data"]["comment"]
                location = st.session_state["redirect_rule_data"]["location"]

                # Store persistent rule identity
                st.session_state["replace_rule_policy"] = selected_policy
                st.session_state["replace_rule_comment"] = selected_comment
                st.session_state["copied_rule_key"] = f"{selected_policy} - {selected_comment}"
                st.session_state["rule_selected"] = st.session_state["copied_rule_key"]

                # Redirect settings
                st.session_state["active_tab"] = "➕ Edit VPN and Firewall Rules !ADMIN!"
                st.session_state["operation_mode"] = "Replace"
                st.session_state["selected_locations"] = [location]

                st.rerun()
            else:
                st.warning("❌ No rule selected for editing. Please select a rule first.")

def get_api_headers(api_key, org_id):
    if org_id == "Systemair":
        org_id_SA = "437647"
        api_key_SA = get_api_key(api_key)
    else:
        org_id_SA = org_id
        api_key_SA = api_key
    st.session_state["org_id"] = org_id_SA
    return {
        "X-Cisco-Meraki-API-Key": api_key_SA,
        "Content-Type": "application/json",
        "X-Cisco-Meraki-Organization-ID": org_id_SA
    }

def fetch_meraki_data(api_key, org_id):
    try:
        headers = get_api_headers(api_key, org_id)
        st.session_state["headers"] = headers
        org_id = st.session_state.get("org_id")
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

def fetch_updated_rules_for_location(network_id, base_url, headers):
    url = f"{base_url}/networks/{network_id}/appliance/firewall/l3FirewallRules"
    resp = requests.get(url, headers=headers)
    return resp.json().get("rules", []) if resp.ok else []

def fetch_updated_vpn_rules(base_url, headers, org_id):
    url = f"{base_url}/organizations/{org_id}/appliance/vpn/vpnFirewallRules"
    resp = requests.get(url, headers=headers)
    return resp.json() if resp.ok else []


def filter_valid_objects(objects_data):
    import ipaddress
    valid = []
    for obj in objects_data:
        cidr = obj.get("cidr", "")
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if str(net.network_address) == cidr.split("/")[0]:
                valid.append(obj)
        except:
            continue
    return valid


def fetch_meraki_data_extended(update_progress=None, base_url="https://api.meraki.com/api/v1"):
    headers = st.session_state.get("headers")
    org_id = st.session_state.get("org_id")
    valid_networks = []
    try:
        
        with st.spinner("🔄 Fetching network list..."):
            networks_url = f"{base_url}/organizations/{org_id}/networks"
            networks_resp = requests.get(networks_url, headers=headers)
            networks = networks_resp.json() if networks_resp.ok else []
            if not networks:
                raise Exception("No networks retrieved")
            excluded_names = {"XX-005-Unclaimed devices", "System Manager", "FR-345-Tillieres-NT"}
            for net in networks:
                if net["name"] in excluded_names:
                    continue
                else:
                    valid_networks.append(net)
            networks = valid_networks

            total = len(networks)
        network_map = {net["name"]: net["id"] for net in networks}

        # NEW: fetch devices from each network
        all_devices = []

        for i, net in enumerate(networks, start=1):
            if update_progress:
                update_progress(i, total, net["name"])
            if st.session_state.get("cancel_extended_fetch"):
                raise Exception("Fetch cancelled by user.")

            network_id = net["id"]
            device_url = f"{base_url}/networks/{network_id}/devices"
            try:
                device_resp = requests.get(device_url, headers=headers)
                if device_resp.ok:
                    for dev in device_resp.json():
                        if dev["model"].startswith(("MS", "C9")):
                            if dev.get("lanIp"):
                                dev["productType"] = "switch"
                            else: 
                                dev["productType"] = "dormant switch"
                        elif dev["model"].startswith(("MR", "CW")):
                            if dev.get("lanIp"):
                                dev["productType"] = "access point"
                            else: 
                                dev["productType"] = "dormant AP"   
                        elif dev["model"].startswith(("MX", "Z")):
                            dev["productType"] = "appliance"   
                        else:
                            dev["productType"] = "unknown" 
                        all_devices.append(dev)


                else:
                    print(f"Failed to fetch devices for {network_id}: {device_resp.status_code}")
            except Exception as e:
                print(f"Error fetching devices for {network_id}: {e}")

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
            "location_map": location_map,
            "devices_data": all_devices,  # NEW
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

def update_snapshot_with_new_rules(locations, api_key, org_id, base_url="https://api.meraki.com/api/v1"):
    headers = {
        "X-Cisco-Meraki-API-Key": api_key,
        "Content-Type": "application/json"
    }

    extended_data = st.session_state.get("extended_data", {})
    network_map = extended_data.get("network_map", {})
    network_details = extended_data.get("network_details", {})

    for loc in locations:

        if loc == "VPN":
            url = f"{base_url}/organizations/{org_id}/appliance/vpn/vpnFirewallRules"
            resp = requests.get(url, headers=headers)
            if resp.ok:
                vpn_rules = resp.json().get("rules", [])
                # VPN rules go into global section - choose any network to attach or store separately
                st.session_state["rules_data"] = vpn_rules  # Global VPN rule override
        else:
            net_id = network_map.get(loc)
            if not net_id:
                continue
            url = f"{base_url}/networks/{net_id}/appliance/firewall/l3FirewallRules"
            resp = requests.get(url, headers=headers)
            if resp.ok:
                new_rules = resp.json().get("rules", [])
                if net_id in network_details:
                    network_details[net_id]["firewall_rules"] = new_rules
    st.session_state["extended_data"]["network_details"] = network_details


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
    devices_data = snapshot.get("devices_data", [])
    return raw_data, object_location_map, devices_data, extended_data



def prepare_snapshot(rules_data, objects_data, groups_data, extended_data, object_location_map, devices_data):
    snapshot = {
        "rules_data": rules_data,
        "objects_data": objects_data,
        "groups_data": groups_data,
        "extended_api_data": extended_data or {},
        "location_map": object_location_map or {},
        "devices_data": devices_data
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"meraki_snapshot_{timestamp}.json"

    return json.dumps(snapshot, indent=2), filename

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

def resolve_names(cidr_str, object_map, group_map):
    parts = [p.strip() for p in cidr_str.split(",")]
    resolved = []
    for p in parts:
        if p.startswith("OBJ(") and p.endswith(")"):
            obj = object_map.get(p[4:-1])
            if obj:
                resolved.append(obj['name'])
            else:
                resolved.append(p)
        elif p.startswith("GRP(") and p.endswith(")"):
            grp = group_map.get(p[4:-1])
            if grp:
                resolved.append(grp['name'])
            else:
                resolved.append(p)
        else:
            resolved.append(p)
    return ", ".join(resolved)

def load_totals_from_comparisons(report_dir=Path("reports")):
    data = []
    for file in sorted(report_dir.glob("dot1x_comparison_*.csv")):
        date_match = re.search(r"dot1x_comparison_(\d{4}-\d{2}-\d{2})\.csv", file.name)
        if date_match:
            date_str = date_match.group(1)
            try:
                df = pd.read_csv(file)
                #st.text(f"Reading {file.name}")
                if "networkname" in df.columns:
                    df["networkname"] = df["networkname"].astype(str).str.lower()
                total_row = df[df["networkname"] == "total"]
                if not total_row.empty:
                    #st.text(f"Found total row in {file.name}")
                    data.append({
                        "date": date_str,
                        "total": int(total_row["current_total"].values[0])
                    })
                #else:
                    #st.warning(f"No TOTAL row in {file.name}")
            except Exception as e:
                st.warning(f"Error reading {file.name}: {e}")
    return pd.DataFrame(data)



def post_updated_rules(network_id, rules):
    url = f"https://api.meraki.com/api/v1/networks/{network_id}/appliance/firewall/l3FirewallRules"
    headers = st.session_state.get("headers")
    body = {"rules": rules}
    response = requests.put(url, headers=headers, json=body)
    return response.status_code, response.json()

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
logo = Image.open("Logo.png")
st.sidebar.image(logo)
st.sidebar.header("Meraki SDWAN Analysis Toolkit V1.1")

#st.sidebar.header("☰ Menu")
st.session_state["api_data_expander"] = False

#st.sidebar.markdown("📦 Load Meraki Dashboard Data")
if st.session_state["Fetch_DATA_Expand_COLLAPSED"] == False:
    
    with st.sidebar.expander("🔽 Load Data", expanded=st.session_state["Fetch_DATA_Expand"]):
        local_snapshot_path = "local_snapshot.json"
        if os.path.exists(local_snapshot_path):
            with open(local_snapshot_path) as f:
                local_data = json.load(f)
            st.session_state["rules_data"] = local_data.get("rules_data", [])
            st.session_state["objects_data"] = local_data.get("objects_data", [])
            st.session_state["groups_data"] = local_data.get("groups_data", [])
            st.session_state["extended_data"] = local_data.get("extended_api_data", {})
            raw_devices_data = local_data.get("devices_data", [])
            if isinstance(raw_devices_data, dict):
                raw_devices_data = list(raw_devices_data.values())
            st.session_state["devices_data"] = raw_devices_data

            st.session_state["object_location_map"] = local_data.get("location_map", {})
            st.success("✅ Loaded snapshot from local storage (offline mode).")
            st.session_state["Fetch_DATA_Expand"] = False
        else:
            st.error("❌ No local snapshot available. Please perform a deploy first.") 
            st.session_state["Fetch_DATA_Expand"] = True
        #org_id = st.text_input("🆔 Enter your Organization ID or Username", value="")
        #api_key = st.text_input("🔑 Enter your Meraki API Key or Password", type="password")
        org_id = st.session_state.get("username")
        api_key = st.session_state.get("password")
        if "headers" not in st.session_state and "username" in st.session_state and "password" in st.session_state:
            st.session_state["headers"] = get_api_headers(st.session_state["password"], st.session_state["username"])

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
                                st.session_state["extended_result"] = fetch_meraki_data_extended(update_progress=update_progress)
                                extended_result = st.session_state.get("extended_result")
                                if st.session_state.get("cancel_extended_fetch"):
                                    st.info("⛔ Fetch cancelled before completion.")
                                    st.session_state["extended_data"] = None
                                    st.session_state["object_location_map"] = {}
                                elif "error" in extended_result:
                                    st.error(f"❌ Error: {extended_result['error']}")
                                    st.session_state["extended_data"] = None
                                    st.session_state["object_location_map"] = {}
                                else:
                                    if isinstance(extended_result, dict):
                                        st.session_state["extended_data"] = {k: v for k, v in extended_result.items() if k != "devices_data"}
                                    else:
                                        st.session_state["extended_data"] = {}

                                    st.session_state["devices_data"] = extended_result.get("devices_data", [])

                                    st.success("✅ Extended Meraki data fetched successfully.")
                                    with st.spinner("🧠 Mapping objects to VPN locations..."):
                                        location_map = build_object_location_map(
                                            st.session_state["objects_data"],
                                            st.session_state["groups_data"],
                                            extended_result
                                        )
                                        st.session_state["object_location_map"] = location_map
                                    snapshot_str, snapshot_filename = prepare_snapshot(
                                        st.session_state.get("rules_data", []),
                                        st.session_state.get("objects_data", []),
                                        st.session_state.get("groups_data", []),
                                        st.session_state.get("extended_data", {}),
                                        st.session_state.get("object_location_map", {}),
                                        st.session_state.get("devices_data=", [])

                                    )
                                    st.session_state["snapshot_str"]      = snapshot_str
                                    st.session_state["snapshot_filename"] = snapshot_filename
                                    st.session_state["snapshot_ready"]    = True

                                    # Convert the string to bytes
                                    data_bytes = snapshot_str.encode('utf-8')

                                    # Create the download button
                                    st.download_button(
                                        label="💾 Download Snapshot",
                                        data=data_bytes,
                                        file_name=snapshot_filename,
                                        mime="application/json"
                                    )
                                    if st.download_button:
                                        st.session_state["Fetch_DATA_Expand"] = False
                                        st.session_state["Fetch_DATA_Expand_COLLAPSED"] = True
                                        local_snapshot_path = "local_snapshot.json"
                                        with open(local_snapshot_path, "w") as f:
                                            json.dump({
                                                "rules_data": st.session_state.get("rules_data", []),
                                                "objects_data": st.session_state.get("objects_data", []),
                                                "groups_data": st.session_state.get("groups_data", []),
                                                "extended_api_data": st.session_state.get("extended_data", {}),
                                                "location_map": st.session_state.get("object_location_map", {}),
                                                "devices_data": st.session_state.get("devices_data", {})
                                            }, f, indent=2)
                                        st.info(f"📦 Local snapshot saved to `{local_snapshot_path}`.")
                                    #safe_rerun()                                
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
            if (
                "objects_data" in st.session_state and
                "groups_data" in st.session_state and
                "extended_data" in st.session_state
            ):
                if "extended_data" in st.session_state and st.session_state["extended_data"]:
                    st.session_state["object_location_map"] = build_object_location_map(
                        st.session_state["objects_data"],
                        st.session_state["groups_data"],
                        st.session_state.get("extended_data")

                    )
                else:
                    st.session_state["object_location_map"] = {}

                #st.write("[✅] Rebuilt object_location_map using latest logic")
        if st.button("📤 Use Local Snapshot"):
            local_snapshot_path = "local_snapshot.json"
            if os.path.exists(local_snapshot_path):
                with open(local_snapshot_path) as f:
                    local_data = json.load(f)
                st.session_state["rules_data"] = local_data.get("rules_data", [])
                st.session_state["objects_data"] = local_data.get("objects_data", [])
                st.session_state["groups_data"] = local_data.get("groups_data", [])
                st.session_state["extended_data"] = local_data.get("extended_api_data", {})
                st.session_state["object_location_map"] = local_data.get("location_map", {})
                
                raw_devices_data = local_data.get("devices_data", {}) 
                if isinstance(raw_devices_data, dict):
                    normalized_devices = list(raw_devices_data.values())
                else:
                    normalized_devices = raw_devices_data
                st.session_state["devices_data"] = normalized_devices
                st.session_state["devices_map"] = {d.get("serial"): d for d in normalized_devices if "serial" in d}

                
                
                st.success("✅ Loaded snapshot from local storage (offline mode).")
            else:
                st.error("❌ No local snapshot available. Please Fetch the Data from API first.")   
            
            
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
                
                
                raw_devices_data = snapshot.get("devices_data", {})  
                if isinstance(raw_devices_data, dict):
                    normalized_devices = list(raw_devices_data.values())
                else:
                    normalized_devices = raw_devices_data
                st.session_state["devices_data"] = normalized_devices
                st.session_state["devices_map"] = {d.get("serial"): d for d in normalized_devices if "serial" in d}

                
                
                if not st.session_state.get("Fetch_DATA_Expand_COLLAPSED"):
                    st.session_state["Fetch_DATA_Expand"] = False
                    st.session_state["Fetch_DATA_Expand_COLLAPSED"] = True
                    
                    safe_rerun() 

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
        devices_data = st.session_state.get("devices_data", {})
else:
    rules_data = st.session_state.get("rules_data", [])
    objects_data = st.session_state.get("objects_data", [])
    groups_data = st.session_state.get("groups_data", [])
    object_map = st.session_state.get("object_map", {})
    group_map = st.session_state.get("group_map", {})
    devices_data = st.session_state.get("devices_data", {})

# -------------- MANUAL TAB HANDLING ----------------
with st.container():
    col_left, col_right = st.columns([6, 13])  # Adjust width ratio as needed

    # LEFT: Label + Selectbox
    with col_left:
        st.markdown(" 📘-🔎-🛡️-🧠 - 📟 - 🌐 - ➕ Choose the module:")
        tab_names = ["📘 Overview", "🔎 Search Object or Group", "🛡️ Search in Firewall and VPN Rules", "🧠 Optimization Insights", "📟 LAN Reports", "🌐 VLAN Configuration !ADMIN!", "➕ Edit VPN and Firewall Rules !ADMIN!"]

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

        col_b, col_n, col_o, col_g, col_r, col_s, col_a, col_ap, col_u = st.columns(9)
        col_b.text("")
        col_r.metric("🛡️ VPN Rules", f"{len(rules_data)}")
        col_o.metric("🌐 Objects", f"{len(objects_data)}")
        col_g.metric("🗃️ Groups", f"{len(groups_data)}")

        extended_data = st.session_state.get("extended_data") or {}
        network_count = len(extended_data.get("network_map", {}))
        col_n.metric("🏢 Networks", network_count)

        # Count device types
        devices = st.session_state.get("devices_data", [])
        switch_count = sum(1 for d in devices if d.get("productType") == "switch")
        dswitch_count = sum(1 for d in devices if d.get("productType") == "dormant switch")
        ap_count = sum(1 for d in devices if d.get("productType") == "access point")
        dap_count = sum(1 for d in devices if d.get("productType") == "dormant AP")
        appliance_count = sum(1 for d in devices if d.get("productType") == "appliance")
        unknown_count = sum(1 for d in devices if d.get("productType") == "unknown")
        col_s.metric("📟 Switches (online/offline)", f"{switch_count} / {dswitch_count}")
        #col_ds.metric("📟 Offline Switches", dswitch_count)
        col_ap.metric("📶 Access Points (online/offline)", f"{ap_count} / {dap_count}")
        #col_da.metric("📶 Offline Access Points", dap_count)
        col_a.metric("🧱 Appliances", appliance_count)
        col_u.metric("Other", unknown_count)

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
            - 🧠 **Optimization Insights**: Get tips on improving your rulebase (e.g., shadowed, duplicate, or broad rules). And Objects & Groups data.
            - 📟 **LAN Reports**: Get reports on switch port's configuration status (Dot1x and Trunk mode)
            - ➕ **Edit VPN and Firewall Rules !ADMIN!**: Create new rules for VPN and local Firewalls.
                        
            👉 **Start by connecting to Meraki or uploading your JSON snapshot in the sidebar.**
            """)
    else:

        with st.expander("📘 About this tab (click to collapse)", expanded=False):
            st.markdown("""
            Use this section to explore how your Networks are configured in terms of VPN settings, subnets and Local Firewall Rules.
            - You can search for a Subnet. 
            - If the subnet is found within SDWAN, the network to which it belongs will be chosen.
            - You can manually pick a network from the dropdown.
            - All Subnets belonging to this Network will be shown with their atributes.
            - Matching objects (exact CIDR match) will be listed.
            - Local Firewall rules for this Network will be also shown
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
                object_map = get_object_map(objects_data)
                group_map = get_group_map(groups_data)
                devices = st.session_state.get("devices_data", [])
                if isinstance(devices, dict):  # back-compat
                    devices = list(devices.values())

                if rules:
                    
                    df = pd.DataFrame([
                        {
                        "Policy": r.get("policy", "").upper(),
                        "Comment": r.get("comment", ""),
                        "Source": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r["srcCidr"].split(",")),
                        "Source Port": r.get("srcPort", ""),
                        "Destination": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r["destCidr"].split(",")),
                        "Destination Port": r.get("destPort", ""),
                        "Protocol": r.get("protocol", "")
                    }
                    for r in rules if "srcCidr" in r and "destCidr" in r
                    ])

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
                    
                
                if selected_network and devices:
                    selected_net_id = network_map.get(selected_network)
                    matching_devices = [d for d in devices if d.get("networkId") == selected_net_id]

                    if matching_devices:
                        st.markdown("### 📟 Devices in this Network")
                        device_table = pd.DataFrame([
                            {
                                "Device Name": d.get("name", "—"),
                                "Type": d.get("productType", "-"),
                                "Model": d.get("model", "—"),
                                "Serial": d.get("serial", "—")
                            }
                            for d in matching_devices
                        ])
                        st.dataframe(device_table, use_container_width=True)  # Moved inside
                    else:
                        st.info("No devices found for this network.")  # Also show this only if no matches

# 🔎 Search Object or Group Tab (Interactive Rebuild)
elif selected_tab == "🔎 Search Object or Group":
    with st.expander("📘 About this tab (click to collapse)", expanded=False):
            st.markdown("""
            Use this section to explore Objects & Groups structure. Here you can:
            - search for a Subnet, Object or Group. 
            - check which Objects are contained in which Group and which Objects and Groups are linked to the Networks (Locations)
            - see in which rules the Object or Group is used 
            """)

    toc_sections = []
    # from utils.match_logic import build_object_location_map

    if "object_location_map" not in st.session_state and "extended_data" in st.session_state and st.session_state["extended_data"]:
        with st.spinner("🧠 Mapping objects to VPN locations..."):
            st.session_state["object_location_map"] = build_object_location_map(
                st.session_state["objects_data"],
                st.session_state["groups_data"],
                st.session_state["extended_data"]
            )

    location_map = st.session_state.get("object_location_map", {})
    extended_data = st.session_state.get("extended_data", {})
    network_details = extended_data.get("network_details", {})
    objects_data = st.session_state.get("objects_data", [])
    groups_data = st.session_state.get("groups_data", [])
    object_map = get_object_map(objects_data)
    group_map = get_group_map(groups_data)

    # Sidebar search
    with st.sidebar:
        search_term = st.text_input("## 🔍 Search by name or CIDR:", "").lower()

    def match_object(obj, term):
        return term in obj.get("name", "").lower() or term in obj.get("cidr", "").lower()

    filtered_objs = [o for o in objects_data if match_object(o, search_term)] if search_term else objects_data
    filtered_grps = [g for g in groups_data if search_term in g.get("name", "").lower()] if search_term else groups_data

            

    toc_sections.append("🔹 Matching Objects")
    
    st.markdown('<a name="matching_objects"></a>', unsafe_allow_html=True)
    st.subheader("🔹 Matching Objects")

    object_rows = []
    for o in filtered_objs:
        cidr = o.get("cidr", "")
        locs = [f"{e['network']} ({'VPN' if e['useVpn'] else 'Local'})" for e in location_map.get(cidr, []) + location_map.get(f"OBJ({o['id']})", []) if isinstance(e, dict)]
        group_names = [group_map[gid]["name"] for gid in o.get("groupIds", []) if gid in group_map]
        object_rows.append({
            "ID": o.get("id", ""),
            "Name": o.get("name", ""),
            "CIDR": cidr,
            "Location": ", ".join(sorted(locs)),
            "Groups": ", ".join(group_names)
        })
    
    df_obj = pd.DataFrame(object_rows)
    st.dataframe(df_obj, use_container_width=True)



    toc_sections.append("🔸 Matching Object Groups")
    
    st.markdown('<a name="matching_groups"></a>', unsafe_allow_html=True)
    st.subheader("🔸 Matching Object Groups")

    group_rows = []
    for g in filtered_grps:
        members = g.get("objectIds", [])
        locs = set()
        for oid in members:
            obj = object_map.get(oid)
            if obj:
                cidr = obj.get("cidr", "")
                for e in location_map.get(cidr, []) + location_map.get(f"OBJ({oid})", []):
                    if isinstance(e, dict):
                        locs.add(f"{e['network']} ({'VPN' if e['useVpn'] else 'Local'})")
        for e in location_map.get(f"GRP({g['id']})", []):
            if isinstance(e, dict):
                locs.add(f"{e['network']} ({'VPN' if e['useVpn'] else 'Local'})")
        group_rows.append({
            "ID": g["id"],
            "Name": g["name"],
            "Object Count": len(members),
            "Location": ", ".join(sorted(locs))
        })

    df_grps = pd.DataFrame(group_rows)
    st.dataframe(df_grps, use_container_width=True)
    
    st.markdown("---")
    col2, col3 = st.columns([4, 6])  # Adjust column width ratios as needed


    with col2:
        selected_obj = st.selectbox(
            "⬇️ Show subnet metadata for CIDR:",
             options=[f"{r['Name']} ({r['CIDR']})" for r in object_rows] if object_rows else [],
             index=0 if object_rows else None
        )
    with col3:
        selected_cidr = selected_obj.split("(")[-1].strip(")") if selected_obj else None
        if selected_cidr:
            # Display metadata here
            #st.markdown(f"**Selected Subnet:** `{selected_cidr}`")
            for net_info in network_details.values():
                for s in net_info.get("vpn_settings", {}).get("subnets", []):
                    if s.get("localSubnet") == selected_cidr:
                        st.write(f"📍 **Network**: {net_info['network_name']}")
                        st.write(f"🔌 **In VPN**: {'✅' if s.get('useVpn') else '❌'}")
                        for meta in s.get('metadata', []):
                            st.write(f"📝 **Name**: {meta.get('name', '—')}")
                            st.write(f"📝 **Type**: {meta.get('type', '—')}")
                        if not s.get('metadata'):
                            st.write("📝 No metadata available.")
    
    st.markdown("---")

    selected_grp = st.selectbox("⬇️ Show members of group:", options=[g["Name"] for g in group_rows] if group_rows else [], index=0 if group_rows else None)
    if selected_grp:
        group_obj = next((g for g in group_rows if g["Name"] == selected_grp), None)
        if group_obj:
            group_id = group_obj["ID"]
            members = [object_map[oid] for oid in group_map.get(group_id, {}).get("objectIds", []) if oid in object_map]
            st.markdown(f"### 👥 Members of `{selected_grp}`")
            st.dataframe(safe_dataframe([
                {
                    "ID": o.get("id"),
                    "Name": o.get("name"),
                    "CIDR": o.get("cidr"),
                    "Location": ", ".join(
                        f"{e['network']} ({'VPN' if e['useVpn'] else 'Local'})"
                        for e in location_map.get(o.get("cidr", ""), [])
                        if isinstance(e, dict)
                    )
                } for o in members
            ]), use_container_width=True)

    st.markdown("---")
    selected_location = st.selectbox("📍 Show all matches for location:", options=sorted({l for row in object_rows + group_rows for l in row.get("Location", "").split(", ") if l.strip()}))
    if selected_location:
        st.markdown(f"### 🌐 Objects matching: `{selected_location}`")
        st.dataframe(safe_dataframe([
            {
                "ID": o.get("id"),
                "Name": o.get("name"),
                "CIDR": o.get("cidr"),
                "FQDN": o.get("fqdn"),
                "Location": ", ".join(sorted(
                    f"{e['network']} ({'VPN' if e['useVpn'] else 'Local'})"
                    for e in location_map.get(o.get("cidr", ""), [])
                    if isinstance(e, dict)
                ))
            } for o in objects_data if selected_location in ", ".join(
                f"{e['network']} ({'VPN' if e['useVpn'] else 'Local'})" for e in location_map.get(o.get("cidr", ""), []) if isinstance(e, dict))
        ]), use_container_width=True)


  
    

    toc_sections.append("📄 Firewall Rules Referencing Selected Object or Group")
    st.subheader("📄 Firewall Rules Referencing Selected Object or Group")
    st.markdown("---")
    st.markdown('<a name="rule_refs"></a>', unsafe_allow_html=True)
   

    # Build combined list: objects first, then groups
    object_or_group_names = (
        [f"🔹 {o['name']}" for o in objects_data] +
        [f"🔸 {g['name']}" for g in groups_data]
    )

    # --- Work out the default selection ------------------------------------
    default_index = 0                                     # fall‑back
    if search_term:                                       # search_term is lower‑cased
        for i, opt in enumerate(object_or_group_names):
            # opt[2:] strips the emoji + space; compare case‑insensitively
            if search_term in opt[2:].lower():
                default_index = i
                break

    selected_ref_entity = st.selectbox(
        "Select object or group:",
        options=object_or_group_names,
        index=default_index if object_or_group_names else None
    )


    rule_refs = []

    if selected_ref_entity:
        entity_name = selected_ref_entity[2:]
        is_object = selected_ref_entity.startswith("🔹")

        # Check both VPN and Local rules
        if is_object:
            match_id = [f"OBJ({o['id']})" for o in objects_data if o['name'] == entity_name]
        else:
            match_id = [f"GRP({g['id']})" for g in groups_data if g['name'] == entity_name]

        match_id = match_id[0] if match_id else None

        if match_id:
            # --- VPN Rules ---
            for i, rule in enumerate(rules_data):
                src_list = [s.strip() for s in rule.get("srcCidr", "").split(",")]
                dst_list = [d.strip() for d in rule.get("destCidr", "").split(",")]

                if match_id in src_list or match_id in dst_list:
                    rule_refs.append({
                        "Type": "VPN",
                        "Location": "(global)",
                        "Number": i + 1,
                        "Comment": rule.get("comment", ""),
                        "Policy": rule.get("policy", "").upper(),
                        "Protocol": rule.get("protocol", ""),
                        "Source": resolve_names(rule.get("srcCidr", ""), object_map, group_map),
                        "SRC Port": rule.get("srcPort", ""),
                        "Destination": resolve_names(rule.get("destCidr", ""), object_map, group_map),
                        "DST Port": rule.get("destPort", "")
                        
                    })

            # --- Local Rules ---
            for net_id, net_info in extended_data.get("network_details", {}).items():
                location = net_info.get("network_name", net_id)
                for i, rule in enumerate(net_info.get("firewall_rules", [])):
                    src_list = [s.strip() for s in rule.get("srcCidr", "").split(",")]
                    dst_list = [d.strip() for d in rule.get("destCidr", "").split(",")]

                    if match_id in src_list or match_id in dst_list:
                        rule_refs.append({
                            "Type": "Local",
                            "Location": location,
                            "Number": i + 1,
                            "Comment": rule.get("comment", ""),
                            "Policy": rule.get("policy", "").upper(),
                            "Protocol": rule.get("protocol", ""),
                            "Source": resolve_names(rule.get("srcCidr", ""), object_map, group_map),
                            "SRC Port": rule.get("srcPort", ""),
                            "Destination": resolve_names(rule.get("destCidr", ""), object_map, group_map),
                            "DST Port": rule.get("destPort", "")
                        })

    if rule_refs:
        st.dataframe(pd.DataFrame(rule_refs), use_container_width=True)
    else:
        st.info("This object or group is not used in any firewall rules.")
    

    with st.sidebar.expander("🧭 Quick Navigation", expanded=True):
        for section in toc_sections:
#            if section.startswith("⚠️"):
 #               st.markdown(f"- [{section}](#problems)")
            if section.startswith("🔹"):
                st.markdown(f"- [{section}](#matching_objects)")
            elif section.startswith("🔸"):
                st.markdown(f"- [{section}](#matching_groups)")
            elif section.startswith("📄"):
                st.markdown(f"- [{section}](#rule_refs)")
        st.markdown("- [⬆️ Back to Top](#top)")


elif selected_tab == "🛡️ Search in Firewall and VPN Rules":
    with st.expander("📘 About this tab (click to collapse)", expanded=False):
            st.markdown("""
            Use this section check the Local and VPN Firewall rules by providing the traffic flow pattern you are interested in.
            As a result you will see which rules will affect the traffic of your interest.
            """)
    all_objects = st.session_state.get("objects_data", [])
    objects_data = filter_valid_objects(all_objects)
    object_map = get_object_map(objects_data)
    group_map = get_group_map(st.session_state.get("groups_data", []))


    # --- Sidebar Controls (Tab-Specific) ---
    with st.sidebar.expander("### ↔️ Traffic Flow", expanded=True):
        #st.markdown("### ↔️ Traffic Flow")
        source_input = st_searchbox(custom_search, label="🌐 Source", placeholder="Object, Group, CIDR, or 'any'", key="src_searchbox", default="any")
        source_port_input = st_searchbox(passthrough_port, label="🔌 Source Port(s)", placeholder="e.g. 80,443", key="srcport_searchbox", default="any")
        destination_input = st_searchbox(custom_search, label="🌐 Destination", placeholder="Object, Group, CIDR, or 'any'", key="dst_searchbox", default="any")
        port_input = st_searchbox(passthrough_port, label="🔌 Destination Port(s)", placeholder="e.g. 443,1000-2000", key="dstport_searchbox", default="any")
        protocol = st_searchbox(search_protocol, label="🧭 Protocol", placeholder="any, tcp, udp...", key="protocol_searchbox", default="any")
        st.markdown("### ⚙️ View Settings")

        if "rule_check_triggered" not in st.session_state:
            st.session_state["rule_check_triggered"] = False

        if st.button("🔍 Search"):
            st.session_state["rule_check_triggered"] = True
            st.session_state["snapshot"] = {
                "src": source_input,
                "dst": destination_input,
                "src_port": source_port_input,
                "dst_port": port_input,
                "protocol": protocol,
            }
            st.session_state["redirect_rule_data"] = {
                "location": "",
                "policy": "",
                "comment": ""
            }
        if not st.session_state["rule_check_triggered"]:
            st.info("Press **Search** to evaluate traffic flow.")
            st.stop()

        filter_toggle = st.checkbox("✅ Show only matching rules", value=st.session_state.get("fw_filter_toggle", True), key="fw_filter_toggle")
        expand_all_local = st.checkbox("🧱 Expand Local Firewall Rule sections", value=st.session_state.get("fw_expand_local", True), key="fw_expand_local")



        highlight_colors = {
            "exact_allow": st.session_state.get("exact_allow", "#09BC8A"),
            "exact_deny": st.session_state.get("exact_deny", "#DA2C38"),
            "partial_allow": st.session_state.get("partial_allow", "#99E2B4"),
            "partial_deny": st.session_state.get("partial_deny", "#F7EF81")
        }


    if not st.session_state.get("rule_check_triggered", False):
        st.info("Press **Search** to evaluate traffic flow.")
        st.stop()

    source_cidrs = resolve_search_input(st.session_state["snapshot"]["src"])
    destination_cidrs = resolve_search_input(st.session_state["snapshot"]["dst"])
    skip_src_check = st.session_state["snapshot"]["src"].strip().lower() == "any"
    skip_dst_check = st.session_state["snapshot"]["dst"].strip().lower() == "any"

    obj_loc_map = st.session_state.get("object_location_map", {})
    extended_data = st.session_state.get("extended_data", {})

  


    if obj_loc_map and extended_data:
        toc_sections = []
        rule_scope = evaluate_rule_scope_from_inputs(source_cidrs, destination_cidrs, obj_loc_map)
        src_locs = rule_scope["src_location_map"]
        dst_locs = rule_scope["dst_location_map"]
        shared_locs = rule_scope["shared_locations"]
        local_rule_locations = rule_scope.get("local_rule_locations", shared_locs)
        show_vpn = rule_scope["vpn_needed"]
        show_local = rule_scope["local_needed"]
        
        # 🔍 Traffic Flow Summary (Refined Layout)
        if st.session_state.get("rule_check_triggered", False):
            src_cidr_list = resolve_search_input(st.session_state["snapshot"]["src"])
            dst_cidr_list = resolve_search_input(st.session_state["snapshot"]["dst"])

            src_cidr_str = ", ".join(src_cidr_list) if src_cidr_list else "any"
            dst_cidr_str = ", ".join(dst_cidr_list) if dst_cidr_list else "any"

            src_port_str = st.session_state["snapshot"]["src_port"].strip() if st.session_state["snapshot"]["src_port"].strip().lower() != "any" else "any"
            dst_port_str = st.session_state["snapshot"]["dst_port"].strip() if st.session_state["snapshot"]["dst_port"].strip().lower() != "any" else "any"
            proto_str = st.session_state["snapshot"]["protocol"].strip().upper() if st.session_state["snapshot"]["protocol"].strip().lower() != "any" else "ANY"

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
                        st.markdown(format_boxed("Source Object", st.session_state["snapshot"]["src"] or "-"), unsafe_allow_html=True)
                        st.markdown(format_boxed("Source CIDR", src_cidr_str), unsafe_allow_html=True)
                        st.markdown(format_boxed("Source Port", st.session_state["snapshot"]["src_port"]), unsafe_allow_html=True)
                        st.markdown(format_boxed("Source Location", src_locs), unsafe_allow_html=True)
                        #st.markdown(format_boxed("Source Networks", src_networks), unsafe_allow_html=True)
                    with col2:
                        st.markdown(format_boxed("Destination Object", st.session_state["snapshot"]["dst"] or "-"), unsafe_allow_html=True)
                        st.markdown(format_boxed("Destination CIDR", dst_cidr_str), unsafe_allow_html=True)
                        st.markdown(format_boxed("Destination Port", st.session_state["snapshot"]["dst_port"]), unsafe_allow_html=True)
                        st.markdown(format_boxed("Destination Location", dst_locs), unsafe_allow_html=True)
                        #st.markdown(format_boxed("Destination Networks", dst_networks), unsafe_allow_html=True)
                    with col3:
                        #st.markdown("<div style='margin-top:1.8em'></div>", unsafe_allow_html=True)
                        st.markdown(format_boxed("Protocol", st.session_state["snapshot"]["protocol"]), unsafe_allow_html=True)
                    st.markdown(format_boxed("Shared Locations",shared_locs), unsafe_allow_html=True)
                    st.markdown("---")



            if show_local and rule_scope.get("local_rule_locations"):
                toc_sections.append("🧱 Local Firewall Rules")
                st.markdown('<a name="local_rules"></a>', unsafe_allow_html=True)
                st.markdown("---")
                st.subheader("🧱 Local Firewall Rules")
                with st.sidebar:
                    location_filter_title = f"📍 Location Filter ({len(local_rule_locations)} found)"
                    all_locations = sorted(set(local_rule_locations))

                    st.session_state.setdefault("selected_local_locations", all_locations)

                    with st.expander(location_filter_title, expanded=True):
                        if st.button("✅ Select All", key="loc_select_all"):
                            st.session_state["selected_local_locations"] = all_locations
                        if st.button("❌ Deselect All", key="loc_deselect_all"):
                            st.session_state["selected_local_locations"] = []

                        valid_selected = [
                            loc for loc in st.session_state.get("selected_local_locations", [])
                            if loc in all_locations
                        ]
                        st.session_state["selected_local_locations"] = valid_selected  # Optional: reset to filtered list

                        st.multiselect(
                            "Pick location(s)",
                            options=all_locations,
                            key="selected_local_locations"
                        )

                        selected_locations = st.session_state["selected_local_locations"]



                seen_locations = set()


                with st.expander(f"Collapse - `{len(selected_locations)}`", expanded=st.session_state["fw_expand_local"]):
                    for location_name in selected_locations:
                        print("🔍 Selected locations for local rules:")
                        print(selected_locations)
                        print("🔍 Available local_rule_locations:")
                        print(local_rule_locations)
                        print("🔍 Final matched extended_data network names:")
                        all_networks = [info.get("network_name") for info in extended_data.get("network_details", {}).values()]
                        print(all_networks)

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
                            anchor = location_name.replace(" ", "_").replace(".", "_")
                            toc_sections.append(f"🔹 {location_name}")
                            st.markdown("---")
                            st.markdown(f'<a name="{anchor}"></a>', unsafe_allow_html=True)
                            st.markdown(f"<h5 style='margin-bottom: 0.5rem; margin-top: 0.5rem;'>🧱 {location_name}</h5>", unsafe_allow_html=True)

                            st.markdown(f"_Total rules: {len(rules)}_")
                            if rules:
                                print(f"🧱 Rendering rules for: {location_name}")
                                print(f"📄 Found network '{location_name}' with net_id '{net_id}'")
                                print(f"📄 Info keys: {list(info.keys())}")
                                print(f"📄 Rules count: {len(info.get('firewall_rules', []))}")
                                generate_rule_table(
                                    rules=rules,
                                    location_name=location_name,
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
                toc_sections.append("🌐 VPN Firewall Rules")
                st.markdown('<a name="vpn_rules"></a>', unsafe_allow_html=True)
                st.markdown("---")
                st.markdown("<h5 style='margin-bottom: 0.5rem;'>🌐 VPN Firewall Rules</h5>", unsafe_allow_html=True)

                st.markdown(f"_Total rules: {len(rules_data)}_")
                generate_rule_table(
                    rules=rules_data,
                    location_name="VPN",
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

        with st.sidebar.expander("### 🧭 Quick Navigation",  expanded=True):
            if toc_sections:
                #st.markdown("### 🧭 Quick Navigation")
                for section in toc_sections:
                    if section == "🧱 Local Firewall Rules":
                        st.markdown(f"- [{section}](#local_rules)")
                    elif section == "🌐 VPN Firewall Rules":
                        st.markdown(f"- [{section}](#vpn_rules)")
                    elif section.startswith("🔹"):
                        anchor = section[2:].replace(" ", "_").replace(".", "_")
                        st.markdown(f"- [{section}](#{anchor})")
                st.markdown("- [⬆️ Back to Top](#top)")  


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
    with st.expander("📘 About this tab (click to collapse)", expanded=False):
            st.markdown("""
            Use this section for optimization and insights. You will find basic reports on inconsistancy or suboptimal configuretion here. 
            """)
    st.markdown('<a name="top"></a>', unsafe_allow_html=True)  # ← anchor for ⬆️ Back to Top

    # Load from session
    extended_data = st.session_state.get("extended_data", {})
    object_map = st.session_state.get("object_map", {})
    group_map = st.session_state.get("group_map", {})
    with st.sidebar.expander("🔑Admin Log-in", expanded=st.session_state.get("expand_login_section", True)):
            if not st.session_state.get("api_key2") and not st.session_state.get("org_id"):
                org_id = st.text_input("🆔 Enter your Organization ID", value="", key="org_id_input")
                api_key = st.text_input("🔑 Enter your Meraki API Key", type="password", key="api_key_input")
                
            else:
                org_id = st.session_state.get("org_id")
                api_key = st.session_state.get("api_key2")
                
                st.markdown(f"🆔 Organization ID: `{org_id}`")
                # Mask part of API key for safety
                masked_key = api_key[:4] + "..." + api_key[-4:] if api_key and len(api_key) > 8 else "****"
                #st.markdown(f"🔑 API Key: `{masked_key}`")
                st.success("✅ API access confirmed.")

            preview_tables = st.session_state.get("preview_tables", {})
            rule_type = st.session_state.get("rule_type", "")

            if st.button("🔍 Check API Access", key="check_api_access"):
                test_url = "https://api.meraki.com/api/v1/organizations"
                st.session_state["org_id"] = org_id
                st.session_state["api_key2"] = api_key
                

                try:
                    test_resp = requests.get(test_url, headers={"X-Cisco-Meraki-API-Key": api_key})
                    if test_resp.ok:
                        st.success("✅ API access confirmed.")
                        st.session_state["expand_login_section"] = False  # use this in `expanded=...`
                        st.session_state["expand_location"] = True
                    else:
                        st.error(f"❌ Access denied. Status code: {test_resp.status_code}")
                    rules_data_c, objects_data_c, groups_data_c, fetched_c = fetch_meraki_data(api_key, org_id)
                    if not rules_data_c == rules_data or not objects_data_c == objects_data or not groups_data_c == groups_data:
                        st.warning("The local snapshot is outdated, please fetch the Data from API")
                        rules_data = rules_data_c
                        objects_data = objects_data_c
                        groups_data = groups_data_c

                    else:
                        st.success("✅ Basic Data is up to date.")
                except Exception as e:
                    st.error(f"❌ Error checking API access: {e}")

        
    org_id = st.session_state.get("org_id")
    api_key = st.session_state.get("api_key2")
    if not extended_data:
        st.warning("Extended data not available. Please fetch Meraki data first.")
        st.stop()
    
    objects_data = st.session_state.get("objects_data", [])
    groups_data  = st.session_state.get("groups_data", [])

    # helpers already used elsewhere
    object_map = get_object_map(objects_data)
    group_map  = get_group_map(groups_data)

    invalid_objects = get_invalid_objects(objects_data)

    if len(invalid_objects) != 0:
        st.markdown('<a name="objects_groups_insights"></a>', unsafe_allow_html=True)
        st.markdown("## ⚠️ Objects and Groups Insights")
    
        st.subheader(f"⚠️ Objects with Invalid CIDRs ({len(invalid_objects)})")
        df_invalid = pd.DataFrame(invalid_objects)
        gb = GridOptionsBuilder.from_dataframe(df_invalid)
        gb.configure_selection('multiple', use_checkbox=True)
        grid_options = gb.build()

        grid_response = AgGrid(
            df_invalid,
            gridOptions=grid_options,
            update_mode='SELECTION_CHANGED',
            height=300,
            fit_columns_on_grid_load=True
        )


        selected_objs = grid_response.get("selected_rows", [])
        if isinstance(selected_objs, pd.DataFrame):
            selected_objs = selected_objs.to_dict(orient="records")

        if selected_objs and st.button("🔧 Fix Selected Objects via API"):
            if org_id and api_key:

                for obj in selected_objs:
                    headers = st.session_state.get("headers")

                    for obj in selected_objs:
                        obj_id = obj["ID"]
                        fix_object_cidr(obj_id, org_id, headers)

                updated_objects = []

                for obj in selected_objs:
                    obj_id = obj["ID"]
                    try:
                        get_url = f"https://api.meraki.com/api/v1/organizations/{org_id}/policyObjects/{obj_id}"
                        get_resp = requests.get(get_url, headers=headers)
                        if get_resp.ok:
                            current_obj = get_resp.json()
                            import ipaddress
                            net = ipaddress.ip_network(obj["CIDR"], strict=False)
                            new_cidr = f"{net.network_address}/{net.prefixlen}"

                            # Update object and send PUT
                            current_obj["cidr"] = new_cidr
                            put_resp = requests.put(get_url, headers=headers, json=current_obj)
                            if put_resp.ok:
                                updated_objects.append(current_obj)

                                # Replace in objects_data
                                for i, o in enumerate(st.session_state["objects_data"]):
                                    if str(o["id"]) == str(obj_id):
                                        st.session_state["objects_data"][i] = current_obj
                                        break

                    except Exception as e:
                        st.error(f"Failed to fix object {obj['Name']}: {e}")

                st.session_state["object_map"] = get_object_map(st.session_state["objects_data"])
            
                # Save updated snapshot
                with open("local_snapshot.json", "w") as f:
                    json.dump({
                        "rules_data": st.session_state.get("rules_data", []),
                        "objects_data": st.session_state.get("objects_data", []),
                        "groups_data": st.session_state.get("groups_data", []),
                        "extended_api_data": st.session_state.get("extended_data", {}),
                        "location_map": st.session_state.get("object_location_map", {}),
                    }, f, indent=2)

                st.success(f"🔧 Fixed {len(updated_objects)} object(s) and updated snapshot.")
                st.rerun()
            else:
                st.warning("Please log in!")

    #   st.dataframe(df_invalid, use_container_width=True)
        st.download_button(
            label="📥 Download Invalid CIDRs Report (CSV)",
            data=df_invalid.to_csv(index=False),
            file_name="invalid_cidrs_report.csv",
            mime="text/csv",
        )


    used_ids = set()

    def extract_ids(cidrs):
        ids = []
        for cid in cidrs.split(","):
            cid = cid.strip()
            if cid.startswith("OBJ(") or cid.startswith("GRP("):
                ids.append(cid)
        return ids

    # Collect all used OBJ(...) and GRP(...) from rules
    for rule in rules_data:
        used_ids.update(extract_ids(rule.get("srcCidr", "")))
        used_ids.update(extract_ids(rule.get("destCidr", "")))
    for net in extended_data.get("network_details", {}).values():
        for rule in net.get("firewall_rules", []):
            used_ids.update(extract_ids(rule.get("srcCidr", "")))
            used_ids.update(extract_ids(rule.get("destCidr", "")))

    # Resolve object IDs used directly or via group membership
    used_object_ids = set()
    used_group_ids = set()

    for used_id in used_ids:
        if used_id.startswith("OBJ("):
            used_object_ids.add(used_id[4:-1])
        elif used_id.startswith("GRP("):
            gid = used_id[4:-1]
            used_group_ids.add(gid)
            grp = group_map.get(gid)
            if grp:
                used_object_ids.update(str(oid) for oid in grp.get("objectIds", []))

    # Find unused objects
    unused_objects = [
        obj for obj in objects_data if str(obj["id"]) not in used_object_ids
    ]

    # Find unused groups
    unused_groups = [
        grp for grp in groups_data if str(grp["id"]) not in used_group_ids
    ]

    if unused_objects:
        st.markdown(f"### 🧹🔹 Unused Network Objects ({len(unused_objects)}):")
        df_unused_obj = (
            pd.DataFrame(unused_objects)[["name", "cidr", "id"]]     # keep existing cols
            .rename(columns={"id": "object_id"})
        )
        st.dataframe(df_unused_obj, use_container_width=True)
    else:
        st.success("✅ All objects are used.")

    # ── 🧹 Unused GROUPS ────────────────────────────────────────────────────
    if unused_groups:
        st.markdown(f"### 🧹🔸 Unused Object Groups ({len(unused_groups)}):")
        df_unused_groups = (
            pd.DataFrame(unused_groups)[["name", "id"]]
            .rename(columns={"id": "group_id"})
        )
        st.dataframe(df_unused_groups, use_container_width=True)

    else:
        st.success("✅ All groups are used.")

        # ── 🔁 Duplicated OBJECTS (same CIDR / FQDN) ───────────────────────────
        
        groups_by_id = {g["id"]: g["name"] for g in groups_data}

        # Build key → [objects] map where key is CIDR or FQDN
        key_to_objs: dict[str, list] = {}
        for obj in objects_data:
            key = obj.get("cidr") or obj.get("fqdn")
            if key:                                       # skip objects without either
                key_to_objs.setdefault(key, []).append(obj)

        duplicate_rows = []
        for key, obj_list in key_to_objs.items():
            if len(obj_list) > 1:                         # keep only real duplicates
                for o in obj_list:
                    used_directly = str(o["id"]) in used_object_ids

                    # ‑‑ group usage check -------------------------------------------------
                    group_ids = o.get("groupIds", [])
                    groups_used = any(str(gid) in used_group_ids for gid in group_ids)
                    group_names = ", ".join(
                        groups_by_id.get(gid, str(gid)) for gid in group_ids
                    )

                    # An object is orphan when it is not used directly and
                    # every group it belongs to is also unused
                    orphan = (not used_directly) and (not groups_used)

                    duplicate_rows.append(
                        {
                            "cidr_or_fqdn": key,
                            "object_name": o["name"],
                            "object_id": o["id"],          # ← NEW visible column
                            "used_in_rule": used_directly,
                            "groups_used": groups_used,
                            "group_names": group_names,    # ← NEW: readable names
                            "orphan": orphan,
                        }
                    )

        if duplicate_rows:
            st.markdown(f"### ⚠️🔁 Duplicated Objects ({len(duplicate_rows)})")
          

            dup_df = (
                pd.DataFrame(duplicate_rows)
                .sort_values(
                    ["cidr_or_fqdn", "orphan", "used_in_rule"],
                    ascending=[True, False, True],         # show orphans first
                )
                .reset_index(drop=True)
            )

            # Re‑order columns explicitly (now interpreted as a list, not a tuple)
            dup_df = dup_df[
                [
                    "cidr_or_fqdn",
                    "object_name",
                    "object_id",
                    "used_in_rule",
                    "groups_used",
                    "group_names",
                    "orphan",
                ]
            ]
            

            st.dataframe(dup_df, use_container_width=True)

            st.download_button(
                label="📥 Download Report (CSV)",
                data=dup_df.to_csv(index=False),     # ← use the correct DataFrame
                file_name="Duplicate_Objects_report.csv",
                mime="text/csv",
            )


        else:
            st.success("✅ No duplicated objects found.")            
    st.markdown('<a name="vpn_rule_insights"></a>', unsafe_allow_html=True)
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
    def analyse_local_rules(rules):
        insights = []
        seen_sigs = set()
        last_idx = len(rules) - 1

        for i, rule in enumerate(rules):
            sig = (rule["policy"], rule["protocol"], rule["srcCidr"],
                rule["destCidr"], rule["destPort"])

            # 1️⃣ Duplicate rule ---------------------------------------------------
            if sig in seen_sigs:
                insights.append((
                    f"🔁 **Duplicate Rule** at index {i + 1}: same action, protocol, source, destination, and port.",
                    [i + 1]
                ))
            else:
                seen_sigs.add(sig)

            # 2️⃣ Broad ANY‑to‑ANY rule risk --------------------------------------
            is_last        = i == last_idx
            is_penultimate = i == last_idx - 1
            is_allow_any   = rule["policy"].lower() == "allow"
            is_deny_any    = rule["policy"].lower() == "deny"

            if (rule["srcCidr"] == "Any" and rule["destCidr"] == "Any"
                    and rule["destPort"].lower() == "any"
                    and rule["protocol"].lower() == "any"):
                if not ((is_allow_any and is_last) or (is_deny_any and is_penultimate)):
                    insights.append((
                        f"⚠️ **Broad Rule Risk** at index {i + 1}: `{rule['policy'].upper()} ANY to ANY on ANY` — may shadow rules below.",
                        [i + 1]
                    ))

            # 3️⃣ Shadowed rule ----------------------------------------------------
            for j in range(i):
                if rule_covers(rules[j], rule):
                    insights.append((
                        f"🚫 **Shadowed Rule** at index {i + 1}: unreachable due to broader rule at index {j + 1}.",
                        [j + 1, i + 1]
                    ))
                    break

            # 4️⃣ Merge candidates with next rule ---------------------------------
            if i < last_idx:
                nxt = rules[i + 1]
                same_core = all(rule[f] == nxt[f] for f in ("policy", "srcCidr", "destCidr"))

                if same_core:
                    # same protocol, diff ports  → merge by port list
                    if rule["protocol"] == nxt["protocol"] and rule["destPort"] != nxt["destPort"]:
                        insights.append((
                            f"🔄 **Merge Candidate** at index {i + 1} & {i + 2}: same action/source/destination, different ports.",
                            [i + 1, i + 2]
                        ))
                    # same ports, diff protocol → merge if one of the ports is 'any'
                    elif (rule["destPort"] == nxt["destPort"]
                        and rule["protocol"] != nxt["protocol"]):
                        if rule["destPort"].lower() == "any" or nxt["destPort"].lower() == "any":
                            insights.append((
                                f"🔄 **Merge Candidate** at index {i + 1} & {i + 2}: same action/src/dst/ports, different protocol.",
                                [i + 1, i + 2]
                            ))

        return insights
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
        vpn_df = pd.DataFrame([
            {
                "Insight": m.split(":")[0].replace("**", "").strip(),
                "Details": m.replace("**", ""),
                "Rule Indexes": ", ".join(map(str, idxs))
            }
            for m, idxs in vpn_insights
        ])
        st.dataframe(vpn_df, use_container_width=True)

        st.download_button(
            "📥 Download VPN Rule Insights (CSV)",
            data=vpn_df.to_csv(index=False),
            file_name="vpn_rule_insights.csv",
            mime="text/csv",
        )
    else:
        st.success("✅ No optimization issues detected in VPN rules.")

    # --- build insights per‑location once -----------------------------------
    st.markdown('<a name="local_rule_insights"></a>', unsafe_allow_html=True)
    location_insights = {}
    for net_id, info in extended_data.get("network_details", {}).items():
        loc = info.get("network_name")
        rules = info.get("firewall_rules", [])
        if not loc:
            continue
        ins = analyse_local_rules(rules)      # <= factor your existing loop
        if ins:                               #    that filled `insight_rows`
            location_insights[loc] = ins

    all_locations = sorted(location_insights.keys())

    with st.sidebar:
        st.markdown("### 📍 Location Filter")

        # Build list of all available locations
        networks = extended_data.get("network_details", {})
        #all_locations = sorted(set(info.get("network_name") for info in networks.values() if info.get("network_name")))

        with st.expander(f"Collapse - `{len(all_locations)}`", expanded=True):
            st.session_state.setdefault("optimization_locations", all_locations)

            if st.button("✅ Select All"):
                st.session_state["optimization_locations"] = all_locations
            if st.button("❌ Deselect All"):
                st.session_state["optimization_locations"] = []

            selected_locations = st.multiselect(
                "Choose locations to analyze:",
                options=all_locations,
                key="optimization_locations"
            )


            seen_locations = set()
        with st.sidebar.expander("🧭 Quick Navigation", expanded=True):
            st.markdown("- [⚠️ Objects and Groups Insights](#objects_groups_insights)")
            st.markdown("- [🌐 VPN Rule Insights](#vpn_rule_insights)")
            st.markdown("- [🧱 Local Rule Insights](#local_rule_insights)")
            st.markdown("- [⬆️ Back to Top](#top)")



    for location in selected_locations:
        st.markdown(f"### 🧠 Optimization Insights for `{location}`")
        rules = next(
            (info.get("firewall_rules", []) for info in extended_data["network_details"].values()
            if info.get("network_name") == location),
            []
        )
        if not rules:
            st.info("No rules found for this location.")
            continue

        insight_rows = location_insights.get(location, [])
        if not insight_rows:
            st.success(f"✅ No optimization issues detected in `{location}`.")
            continue

        # ── UI ────────────────────────────────────────────────────────────────
        with st.expander(f"🧱 Local Rules Optimization Details – {location}", expanded=False):
            loc_df = pd.DataFrame([
                {
                    "Insight": m.split(":")[0].replace("**", "").strip(),
                    "Details": m.replace("**", ""),
                    "Rule Indexes": ", ".join(map(str, idxs))
                }
                for m, idxs in insight_rows
            ])
            st.dataframe(loc_df, use_container_width=True)
            st.download_button(
                f"📥 Download Local Insights – {location} (CSV)",
                data=loc_df.to_csv(index=False),
                file_name=f"local_rule_insights_{location}.csv",
                mime="text/csv",
            )

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

elif selected_tab == "➕ Edit VPN and Firewall Rules !ADMIN!":

    def get_original_rules_for(loc):
        if loc == "VPN":
            return st.session_state.get("rules_data", [])
        else:
            net_id = st.session_state["extended_data"]["network_map"].get(loc)
            return st.session_state["extended_data"]["network_details"].get(net_id, {}).get("firewall_rules", [])

    def rules_equivalent_ignoring_default(rules1, rules2):
        def strip_default(r):
            return [rule for rule in r if not (
                rule.get("comment", "").strip().lower() == "default rule"
                and rule.get("policy", "").lower() == "allow"
                and rule.get("protocol", "").lower() == "any"
                and rule.get("srcPort", "").lower() == "any"
                and rule.get("destPort", "").lower() == "any"
                and rule.get("srcCidr", "").lower() == "any"
                and rule.get("destCidr", "").lower() == "any"
            )]
        return strip_default(rules1) == strip_default(rules2)
    
    if "expand_login_section" not in st.session_state:
        st.session_state["expand_login_section"] = True
    if "expand_location" not in st.session_state:
        st.session_state["expand_location_section"] = False
    data_loaded = (
        st.session_state.get("rules_data")
        and st.session_state.get("objects_data")
        and st.session_state.get("extended_data")
    )

    if data_loaded:
    
        if "preview_tables" not in st.session_state:
            st.session_state["preview_tables"] = {}
        if "selected_locations" not in st.session_state:
            st.session_state["selected_locations"] = []
        if "show_table" not in st.session_state:
            st.session_state["show_table"] = False
        if "rule_type" not in st.session_state:
            st.session_state["rule_type"] = "Local"

        # Load API data
        extended_data = st.session_state["extended_data"]
        objects_data = st.session_state["objects_data"]
        groups_data = st.session_state["groups_data"]
        network_details = extended_data["network_details"]
        network_map = extended_data["network_map"]
        object_map = {v["name"]: v["id"] for v in objects_data}
        group_map = {v["name"]: v["id"] for v in groups_data}

        # Construct location list with VPN included
        network_names = sorted([v["network_name"] for v in network_details.values()])
        all_locations = ["VPN"] + network_names
        with st.sidebar.expander("🔑Admin Log-in", expanded=st.session_state.get("expand_login_section", True)):
            if not st.session_state.get("org_id"):
                org_id = st.text_input("🆔 Enter your Organization ID", value="", key="org_id_input")
            else:
                org_id = st.session_state.get("org_id")
                st.markdown(f"🆔 Organization ID: `{org_id}`")
    

            if not st.session_state.get("api_key2"):
                api_key = st.text_input("🔑 Enter your Meraki API Key", type="password", key="api_key_input")
                
            else:
                api_key = st.session_state.get("api_key2")
                masked_key = api_key[:4] + "..." + api_key[-4:] if api_key and len(api_key) > 8 else "****"
                #st.markdown(f"🔑 API Key: `{masked_key}`")
                st.success("✅ API access confirmed.")

            preview_tables = st.session_state.get("preview_tables", {})
            rule_type = st.session_state.get("rule_type", "")

            if st.button("🔍 Check API Access", key="check_api_access"):
                test_url = "https://api.meraki.com/api/v1/organizations"
                st.session_state["org_id"] = org_id
                st.session_state["api_key2"] = api_key
                

                try:
                    test_resp = requests.get(test_url, headers={"X-Cisco-Meraki-API-Key": api_key})
                    if test_resp.ok:
                        st.success("✅ API access confirmed.")
                        st.session_state["expand_login_section"] = False  # use this in `expanded=...`
                        st.session_state["expand_location"] = True
                    else:
                        st.error(f"❌ Access denied. Status code: {test_resp.status_code}")
                    rules_data_c, objects_data_c, groups_data_c, fetched_c = fetch_meraki_data(api_key, org_id)
                    if not rules_data_c == rules_data or not objects_data_c == objects_data or not groups_data_c == groups_data:
                        st.warning("The local snapshot is outdated, please fetch the Data from API")
                        rules_data = rules_data_c
                        objects_data = objects_data_c
                        groups_data = groups_data_c

                    else:
                        st.success("✅ Basic Data is up to date.")
                except Exception as e:
                    st.error(f"❌ Error checking API access: {e}")

        
        with st.sidebar:
            col0, col1 = st.columns([1, 1])
            with col0:
                if st.button("⛔ Reset Changes", key="reset_button"):
                    st.session_state["preview_tables"] = {}
                    st.session_state["show_table"] = False
                    st.session_state["rule_type"] = ""
                    st.success("All changes have been reset.")
                    st.session_state["show_table"] = False
                    st.session_state["Restore_done"] = False
                    st.session_state["Deploy_Checked"] = False
            with col1:
                if st.button("🆗 Confirm Changes"):
                    pending_locs = []
                    for loc, rules in st.session_state["preview_tables"].items():
                        cleaned_rules = [r for r in rules if not r.get("is_deleted", False)]
                        original = get_original_rules_for(loc)
                        if not rules_equivalent_ignoring_default(cleaned_rules, original):
                            pending_locs.append(loc)
                    if not pending_locs and st.session_state["operation_mode"] in ("Restore", "Use Template"):
                        pending_locs = st.session_state.get("current_selected_locations")
                    st.success("All changes have been confirmed.")
                    st.session_state["selected_rule_key"] = None
                    st.session_state["set_pending_locations"] = sorted(pending_locs)
                    st.session_state["show_table"] = True
                    st.session_state["force_show_all_rules"] = True  # ← NEW FLAG
                    st.session_state["Deploy_Checked"] = True
                    st.session_state["Restore_done"] = None
                    
                    #st.rerun()
                     
        with st.sidebar:
            if st.button("🚀 Deploy Changes", key="deploy_button") and preview_tables and st.session_state["expand_location"] == True:
                if st.session_state["Deploy_Checked"] == True:
                    successful_deployments = []
                    api_key = st.session_state["api_key2"]
                    headers = {"X-Cisco-Meraki-API-Key": api_key, "Content-Type": "application/json"}
                    current_selected_locations = st.session_state.get("selected_locations", [])
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    total = len(current_selected_locations)
                    #st.markdown(preview_tables)
                    for i, loc in enumerate(current_selected_locations, start=1):
                        progress = i / total
                        progress_bar.progress(progress)
                        status_text.markdown(f"🚀 Deploying `{loc}` ({i}/{total})")
                        rules = preview_tables.get(loc)
                        if not rules:
                            st.warning(f"No rules found for `{loc}`.")
                            continue
                        if loc == "VPN":
                            url = f"https://api.meraki.com/api/v1/organizations/{org_id}/appliance/vpn/vpnFirewallRules"
                        else:
                            net_id = network_map.get(loc)
                            url = f"https://api.meraki.com/api/v1/networks/{net_id}/appliance/firewall/l3FirewallRules"
                        try:
                            def is_default_rule(rule):
                                return (
                                    rule.get("comment", "").strip().lower() == "default rule"
                                    and rule.get("policy", "").lower() == "allow"
                                    and rule.get("protocol", "").lower() == "any"
                                    and rule.get("srcPort", "").lower() == "any"
                                    and rule.get("destPort", "").lower() == "any"
                                    and rule.get("srcCidr", "").lower() == "any"
                                    and rule.get("destCidr", "").lower() == "any"
                                )

                            cleaned_rules = [r for r in rules if not r.get("is_deleted", False)]

                            original = get_original_rules_for(loc)  # Define a function to fetch the original rule list
                            if rules_equivalent_ignoring_default(cleaned_rules, original):
                                continue

                            filtered_rules = [
                                r for r in rules
                                if not r.get("is_deleted", False) and not is_default_rule(r)
                            ]

                            
                            api_rules = [
                                {k: v for k, v in rule.items() if k not in {"is_deleted", "is_new"}}
                                for rule in filtered_rules
                            ]
                            if loc == "VPN":
                                json_body={"rules": api_rules, "syslogDefaultRule": False}
                            else:
                                json_body={"rules": api_rules}
                            
                            resp = requests.put(
                                url,
                                headers=headers,
                                json=json_body,
                            )
                            if resp.ok:
                                st.session_state.setdefault("rule_log", []).append(f"✅ {loc}: Deployed (Status {resp.status_code})")
                                successful_deployments.append(loc)
                            else:
                                st.code(url)
                                st.code(json.dumps(json_body, indent=2), language="json")
                                st.session_state.setdefault("rule_log", []).append(f"❌ {loc}: Failed (Status {resp.status_code})")
                        except Exception as e:
                            st.session_state.setdefault("rule_log", []).append(f"❌ {loc}: Deployment error - {e}")
                    # Display log
                    for entry in st.session_state.get("rule_log", []):
                        st.markdown(f"- {entry}")
                    # Clear preview state
                    st.session_state["preview_tables"] = {}
                    st.session_state["rule_type"] = ""
                    preview_tables = {}
                    rule_type = ""
                    # Update only deployed parts of snapshot
                    if successful_deployments:
                        update_snapshot_with_new_rules(successful_deployments, api_key, org_id)
                        snapshot_str, snapshot_filename = prepare_snapshot(
                            st.session_state.get("rules_data", []),
                            st.session_state.get("objects_data", []),
                            st.session_state.get("groups_data", []),
                            st.session_state.get("extended_data", {}),
                            st.session_state.get("object_location_map", {}),
                            st.session_state.get("devices_data=", [])
                        )
                        local_snapshot_path = "local_snapshot.json"
                        with open(local_snapshot_path, "w") as f:
                            json.dump({
                                "rules_data": st.session_state.get("rules_data", []),
                                "objects_data": st.session_state.get("objects_data", []),
                                "groups_data": st.session_state.get("groups_data", []),
                                "extended_api_data": st.session_state.get("extended_data", {}),
                                "location_map": st.session_state.get("object_location_map", {}),
                            }, f, indent=2)
                        st.info(f"📦 Local snapshot saved to `{local_snapshot_path}`.")

                        st.download_button(
                            "📥 Download Updated Snapshot",
                            data=snapshot_str,
                            file_name=snapshot_filename,
                            mime="application/json",
                        )

                    progress_bar.empty()
                    status_text.empty()

                else:
                    pending_locs = []
                    for loc, rules in st.session_state["preview_tables"].items():
                        cleaned_rules = [r for r in rules if not r.get("is_deleted", False)]
                        original = get_original_rules_for(loc)
                        if not rules_equivalent_ignoring_default(cleaned_rules, original):
                            pending_locs.append(loc)

                    st.warning("Please confirm changes before deploying.")
                    st.session_state["selected_rule_key"] = None
                    st.session_state["set_pending_locations"] = sorted(pending_locs)
                    st.session_state["show_table"] = True
                    st.session_state["force_show_all_rules"] = True
        
        # Collect all rule comment-policy pairs and map to locations
        rule_to_locations = {}
        for net_id, net_info in st.session_state["extended_data"]["network_details"].items():
            net_name = net_info["network_name"]
            for rule in net_info.get("firewall_rules", []):
                key = f"{rule.get('policy', '').upper()} - {rule.get('comment', '')}"
                rule_to_locations.setdefault(key, []).append(net_name)

        # Also include VPN rules if applicable
        for rule in st.session_state.get("rules_data", []):
            key = f"{rule.get('policy', '').upper()} - {rule.get('comment', '')}"
            rule_to_locations.setdefault(key, []).append("VPN")

        rule_keys_sorted = sorted(rule_to_locations.keys())
        # --- SIDEBAR: Location Selector ---
        with st.sidebar.expander("🎯 Target Locations", expanded=st.session_state.get("expand_location", False)):

            selected_locs = st.session_state.get("selected_locations", [])
            if selected_locs:
                rule_sets = []
                for loc in selected_locs:
                    if loc == "VPN":
                        rules = st.session_state.get("rules_data", [])
                    else:
                        net_id = network_map.get(loc)
                        rules = network_details.get(net_id, {}).get("firewall_rules", [])
                    rule_set = set(f"{r.get('policy', '').upper()} - {r.get('comment', '')}" for r in rules)
                    rule_sets.append(rule_set)
                common_rule_keys = sorted(set.intersection(*rule_sets)) if rule_sets else []
            else:
                common_rule_keys = sorted(rule_to_locations.keys())

            rule_options = [""] + common_rule_keys

            # Force "" if requested
            if st.session_state.pop("force_show_all_rules", False):
                selected_rule_filter = ""
            else:
                selected_rule_filter = st.session_state.get("selected_rule_key", "")
                if selected_rule_filter not in rule_options:
                    selected_rule_filter = ""

            selected_rule_filter = st.selectbox(
                "Search Rule by Comment",
                rule_options,
                index=rule_options.index(selected_rule_filter)
            )
            st.session_state["selected_rule_key"] = selected_rule_filter if selected_rule_filter != "" else None

            rule_filter_mode = st.radio("Filter Mode", ["Show Locations with Rule", "Show Locations without Rule"], horizontal=True)

            all_locations = ["VPN"] + [net["network_name"] for net in network_details.values()]

            if selected_rule_filter != "":
                present = set(rule_to_locations.get(selected_rule_filter, []))
                all_locs = set(all_locations)
                if rule_filter_mode == "Show Locations with Rule":
                    filtered_locations = sorted(present)
                else:
                    filtered_locations = sorted(all_locs - present)
            else:
                filtered_locations = [name for name in all_locations if name == "VPN" or network_details[network_map[name]].get("firewall_rules")]

            if "set_pending_locations" in st.session_state:
                pending = st.session_state.pop("set_pending_locations")
                st.session_state["selected_locations"] = [loc for loc in pending if loc in filtered_locations]

            if st.button("✅ Select All"):
                st.session_state["selected_locations"] = filtered_locations
            if st.button("❌ Deselect All"):
                st.session_state["selected_locations"] = []

            st.multiselect("Locations", filtered_locations, key="selected_locations")
            st.session_state["expand_deploy_section"] = False

        # --- MAIN LAYOUT ---
        st.session_state["rule_type"] = rule_type

        selected_locations = st.session_state["selected_locations"]
        st.markdown('<a name="top_of_page"></a>', unsafe_allow_html=True)
        # Define helper functions
        def id_to_name(cid, obj_map, grp_map):
            if cid.startswith("OBJ("):
                return next((name for name, id_ in obj_map.items() if id_ == cid[4:-1]), cid)
            elif cid.startswith("GRP("):
                return next((name for name, id_ in grp_map.items() if id_ == cid[4:-1]), cid)
            return cid

        def ShowRulesPreview(new_rule, match_comment, match_policy, new_comment, action, insert_position, delete_rule=False):

            
            preview_tables = {}

            for loc in selected_locations:
                is_vpn = loc == "VPN"
                if is_vpn:
                    rule_list = copy.deepcopy(st.session_state["preview_tables"].get("VPN", st.session_state.get("rules_data", [])))
                    rule_type = "VPN"
                else:
                    net_id = network_map.get(loc)
                    rule_list = copy.deepcopy(st.session_state["preview_tables"].get(loc, network_details[net_id].get("firewall_rules", [])))
                    rule_type = "Local"
                if delete_rule and match_comment:
                    for r in rule_list:
                        if r.get("comment", "") == match_comment and r.get("policy", "").lower() == match_policy.lower():
                            r["is_deleted"] = True

                if new_rule:
                    insert_index = next((i for i, r in enumerate(rule_list)
                                        if r.get("comment", "") == match_comment and r.get("policy", "").lower() == match_policy.lower()), None)

                    # Adjust insertion logic
                    if insert_position == "Bottom":
                        index = max(len(rule_list) - 1, 0)
                        rule_list.insert(index, new_rule)
                    elif insert_position == "Top":
                        rule_list.insert(0, new_rule)
                    elif insert_position == "Above" and insert_index is not None:
                        rule_list.insert(insert_index, new_rule)
                    elif insert_position == "Below" and insert_index is not None:
                        if insert_index + 1 >= len(rule_list):
                            st.warning("Cannot insert a rule after the Default rule.")
                        else:
                            rule_list.insert(insert_index + 1, new_rule)
                    else:
                        rule_list.append(new_rule)
                if is_vpn:
                    st.session_state["preview_tables"]["VPN"] = rule_list
                else:
                    st.session_state["preview_tables"][loc] = rule_list

                preview_tables[loc] = rule_list
        
            if operation_mode in ["Use Template", "Backup", "Restore"]:
                for loc, rules in preview_tables.items():
                    df = pd.DataFrame([
                        {
                            "Rule Index": idx,
                            "Policy": r.get("policy", "").upper(),
                            "Comment": r.get("comment", ""),
                            "Source": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r["srcCidr"].split(",")),
                            "Source Port": r.get("srcPort", ""),
                            "Destination": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r["destCidr"].split(",")),
                            "Destination Port": r.get("destPort", ""),
                            "Protocol": r.get("protocol", ""),
                            "is_new": operation_mode == "Add" and r.get("comment") == new_comment and r.get("policy") == action,
                            "is_deleted": r.get("is_deleted", False)

                        }
                        for idx, r in enumerate(rules) if "srcCidr" in r and "destCidr" in r
                    ])
                    gb = GridOptionsBuilder.from_dataframe(df)
                    gb.configure_default_column(filter=True, sortable=True, resizable=True, wrapText=True, autoHeight=True)
                    gb.configure_grid_options(domLayout="autoHeight")
                    grid_options = gb.build()
                    row_style_js = JsCode("""
                    function(params) {
                        if (params.data.is_deleted) {
                            return {
                                backgroundColor: '#f0f0f0',
                                color: '#888',
                                fontStyle: 'italic',
                                textDecoration: 'line-through'
                            };
                        }
                        if (params.data.is_new) {
                            return {
                                backgroundColor: '#D0E7FF',
                                color: '#003366',
                                fontWeight: 'bold'
                            };
                        }
                        if (params.data.Policy === "ALLOW") {
                            return {
                                backgroundColor: '#99E2B4',
                                color: '#155724',
                                fontWeight: 'bold'
                            };
                        }
                        if (params.data.Policy === "DENY") {
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
                    st.markdown(f"📄 Showing **{len(df)}** rules for `{loc}`")
                    AgGrid(
                        df,
                        gridOptions=grid_options,
                        enable_enterprise_modules=False,
                        fit_columns_on_grid_load=True,
                        use_container_width=True,
                        allow_unsafe_jscode=True,
                        key=f"Grid_{loc}"
                        )
            else:

                for loc, rules in preview_tables.items():
                    df = pd.DataFrame([
                        {
                            "Rule Index": idx,
                            "Policy": r.get("policy", "").upper(),
                            "Comment": r.get("comment", ""),
                            "Source": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r["srcCidr"].split(",")),
                            "Source Port": r.get("srcPort", ""),
                            "Destination": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r["destCidr"].split(",")),
                            "Destination Port": r.get("destPort", ""),
                            "Protocol": r.get("protocol", ""),
                            "is_new": operation_mode == "Add" and r.get("comment") == new_comment and r.get("policy") == action,
                            "is_deleted": r.get("is_deleted", False)

                        }
                        for idx, r in enumerate(rules) if "srcCidr" in r and "destCidr" in r
                    ])

                    row_style_js = JsCode("""
                    function(params) {
                        if (params.data.is_deleted) {
                            return {
                                backgroundColor: '#f0f0f0',
                                color: '#888',
                                fontStyle: 'italic',
                                textDecoration: 'line-through'
                            };
                        }
                        if (params.data.is_new) {
                            return {
                                backgroundColor: '#D0E7FF',
                                color: '#003366',
                                fontWeight: 'bold'
                            };
                        }
                        if (params.data.Policy === "ALLOW") {
                            return {
                                backgroundColor: '#99E2B4',
                                color: '#155724',
                                fontWeight: 'bold'
                            };
                        }
                        if (params.data.Policy === "DENY") {
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
                    gb.configure_grid_options(rowSelection='single')
                    gb.configure_selection('single')
                    grid_options = gb.build()
                    
                    st.markdown(f"📄 Showing **{len(df)}** rules for `{loc}`")
                    label_map = {
                            #"Add": "📌 Set as Anchor Rule",
                        "Delete": "🗑️ Select Rule",
                        "Copy": "📋 Select Rule",
                        "Replace": "✏️ Select Rule"
                    }
                    
                    grid_response = AgGrid(
                        df,
                        gridOptions=grid_options,
                        enable_enterprise_modules=False,
                        fit_columns_on_grid_load=True,
                        use_container_width=True,
                        allow_unsafe_jscode=True,
                        key=f"Grid_{loc}",
                        update_mode=GridUpdateMode.SELECTION_CHANGED,
                        selection_mode="single"
                        )
                    
                    if "redirect_rule_data" not in st.session_state:
                        st.session_state["redirect_rule_data"] = {}

                    selected_rows = grid_response.get("selected_rows", [])
                    if isinstance(selected_rows, pd.DataFrame):
                        selected_rows = selected_rows.to_dict(orient="records")
                
                    if isinstance(selected_rows, list) and selected_rows:
                        selected_row = selected_rows[0]
                        
                        st.session_state["redirect_rule_data"] = {
                            "policy": selected_row.get("Policy", "").upper(),
                            "comment": selected_row.get("Comment", "")
                        }
                        with st.sidebar:
                            if operation_mode == "Replace":
                                st.success(f"✅ Rule {selected_row.get('Comment', '')} selected for edit.")
                            elif operation_mode == "Delete":
                                st.success(f"✅ Rule {selected_row.get('Comment', '')} selected for deletion.")
                            elif operation_mode == "Copy":
                                st.success(f"✅ Rule {selected_row.get('Comment', '')} selected for copy.")
                            if operation_mode != "Add":
                                button_label = label_map.get(st.session_state.get("operation_mode"), "✏️ Edit Rule")
                                if st.button(button_label, {loc}):
                                    #st.write("Redirect Data:", st.session_state.get("redirect_rule_data"))
                                    if st.session_state.get("operation_mode") == "Add" and len(selected_locations) > 1:
                                        st.info("ℹ️ Rule selection from table is disabled when multiple locations are selected in Add mode.")
                                    else:
                                        if st.session_state.get("redirect_rule_data"):
                                            pol = st.session_state["redirect_rule_data"]["policy"]
                                            com = st.session_state["redirect_rule_data"]["comment"]
                                            st.session_state["replace_rule_policy"] = pol
                                            st.session_state["replace_rule_comment"] = com

                                            selected_key = f"{pol} - {com}"
                                            st.session_state["rule_selected"] = selected_key

                                            if st.session_state.get("operation_mode") == "Add":
                                                st.session_state["insert_position"] = "Above"
                                            else:
                                                st.session_state["copied_rule_key"] = selected_key
                                            
                                            st.rerun()
                                            st.query_params(scroll_to="top")

                                        else:
                                            st.warning("❌ No rule selected for editing. Please select a rule first.")    

        def ShowRestorePreview():
            if st.session_state.get("Restore_done") == None:
                st.session_state["Restore_done"] = True
                
        # Input Form
        
        all_options = sorted(set(object_map) | set(group_map) | {"Any"})
        with st.expander("➕ Parameters", expanded=True):
            operation_mode = st.session_state.get("operation_mode")
            #st.markdown('<a name="top"></a>', unsafe_allow_html=True)
            col0, col1, col2 = st.columns([6, 5, 8])
            with col0:
                #operation_mode = st.radio("Operation", ["Add", "Delete", "Copy", "Replace", "Backup", "Restore"], horizontal=True, key="operation_mode")
                operation_mode = st.radio(
                    "Operation",
                    ["Delete", "Copy", "Add", "Replace", "Use Template", "Backup", "Restore"],
                    horizontal=True,
                    key="operation_mode"  # state-backed
                )

                if operation_mode == "Add":
                    st.session_state["persist_rule"] = st.checkbox("➕     Keep rule and continue adding", value=False)
                if operation_mode == "Use Template":
                    st.markdown("**Important:** This will replace all existing rules for the locations chosen with the template data.")
            with col1:
                if operation_mode == "Add":
                    insert_position = st.selectbox("Insert Position", ["Above", "Below", "Top", "Bottom"])
                else:
                    insert_position = "This"  # placeholder to keep later function calls consistent

            with col2:
                rule_options = []
                rule_sets = []
                first_loc_rules = []
                if operation_mode in ["Replace", "Delete", "Copy", "Add"]:
                    rule_sets = []
                    first_loc_rules = []
                    all_loc_rules = []

                    for idx, loc in enumerate(selected_locations):
                        rules = st.session_state["rules_data"] if loc == "VPN" else network_details.get(network_map[loc], {}).get("firewall_rules", [])
                        loc_rule_set = set((r.get("policy", ""), r.get("comment", "")) for r in rules)
                        rule_sets.append(loc_rule_set)

                        loc_rules = [(r.get("policy", ""), r.get("comment", "")) for r in rules]
                        all_loc_rules.extend(loc_rules)

                        if idx == 0:
                            first_loc_rules = loc_rules

                    if operation_mode == "Copy":
                        # Show union of all rules across selected locations
                        rule_options = [f"{p.upper()} - {c}" for p, c in sorted(set(all_loc_rules))]
                        selected_rule_key = st.session_state.get("copied_rule_key")
                    else:
                        # Show only common rules across all locations
                        common_rules = set.intersection(*rule_sets) if rule_sets else set()
                        rule_options = [f"{p.upper()} - {c}" for p, c in first_loc_rules if (p, c) in common_rules]
                        selected_rule_key = st.session_state.get("rule_selected")

                    selected_index = rule_options.index(selected_rule_key) if selected_rule_key in rule_options else 0 if rule_options else None


                    label_map = {
                        "Add": "Match Existing Rule",
                        "Delete": "Select Rule to Delete",
                        "Copy": "Select Rule to Copy",
                        "Replace": "Select Rule to Replace"
                    }
                    select_label = label_map.get(operation_mode, "Select Rule")

                    selected_rule = st.selectbox(select_label, rule_options, index=selected_index)

                    # Handle selection by operation
                    if selected_rule:
                        match_policy, match_comment = selected_rule.split(" - ", 1)

                        if operation_mode == "Copy":
                            st.session_state["copied_rule_key"] = selected_rule
                            st.session_state["rule_selected"] = selected_rule
                            st.session_state["replace_rule_policy"] = match_policy
                            st.session_state["replace_rule_comment"] = match_comment
                            if selected_locations:
                                st.session_state["copied_rule_location"] = selected_locations[0]

                        elif operation_mode == "Add":
                            # Don't touch copied_rule_key; just set anchor
                            st.session_state["rule_selected"] = selected_rule
                            st.session_state["replace_rule_policy"] = match_policy
                            st.session_state["replace_rule_comment"] = match_comment

                        else:
                            st.session_state["copied_rule_key"] = selected_rule
                            st.session_state["rule_selected"] = selected_rule
                            st.session_state["replace_rule_policy"] = match_policy
                            st.session_state["replace_rule_comment"] = match_comment


                
                elif operation_mode == "Use Template":
                    uploaded_file = st.file_uploader("📤 Upload Template", type="json", key="restore_snapshot_upload")
                    if uploaded_file:
                        try:
                            restore_data = json.load(uploaded_file)
                            st.session_state["restore_rules_data"] = restore_data
                            ShowRestorePreview()
                            st.success("✅ Template loaded.")
                        except Exception as e:
                            st.error(f"❌ Failed to parse snapshot: {e}")

                elif operation_mode == "Backup":
                    if st.button("📥 Fetch Update for Selected Locations"):
                        if api_key:
                            selected_locations = st.session_state.get("selected_locations", [])
                            if selected_locations:
                                progress_bar = st.progress(0)
                                status_text = st.empty()

                                total = len(selected_locations)
                                for i, loc in enumerate(selected_locations, start=1):
                                    progress = i / total
                                    progress_bar.progress(progress)
                                    status_text.markdown(f"🔄 Updating snapshot with rules from `{loc}` ({i}/{total})")
                                    update_snapshot_with_new_rules([loc], st.session_state["api_key2"], st.session_state["org_id"])
                                snapshot_str, snapshot_filename = prepare_snapshot(
                                    st.session_state.get("rules_data", []),
                                    st.session_state.get("objects_data", []),
                                    st.session_state.get("groups_data", []),
                                    st.session_state.get("extended_data", {}),
                                    st.session_state.get("object_location_map", {}),
                                    st.session_state.get("devices_data=", [])
                                )
                                st.session_state["backup_snapshot_str"] = snapshot_str
                                st.session_state["backup_snapshot_filename"] = snapshot_filename
                                st.success("✅ Snapshot updated with selected locations.")
                                local_snapshot_path = "local_snapshot.json"
                                with open(local_snapshot_path, "w") as f:
                                    json.dump({
                                        "rules_data": st.session_state.get("rules_data", []),
                                        "objects_data": st.session_state.get("objects_data", []),
                                        "groups_data": st.session_state.get("groups_data", []),
                                        "extended_api_data": st.session_state.get("extended_data", {}),
                                        "location_map": st.session_state.get("object_location_map", {}),
                                    }, f, indent=2)
                                st.info(f"📦 Local snapshot saved to `{local_snapshot_path}`.")

                                st.download_button(
                                    "📥 Download Updated Snapshot",
                                    data=snapshot_str,
                                    file_name=snapshot_filename,
                                    mime="application/json",
                                )
                        else:
                            st.warning("Please check your API credentials!")
                elif operation_mode == "Restore":
                    uploaded_file = st.file_uploader("📤 Upload Snapshot for Restore", type="json", key="restore_snapshot_upload")
                    if uploaded_file:
                        try:
                            restore_data = json.load(uploaded_file)
                            st.session_state["restore_rules_data"] = restore_data.get("rules_data", [])
                            st.session_state["restore_objects_data"] = restore_data.get("objects_data", [])
                            st.session_state["restore_groups_data"] = restore_data.get("groups_data", [])
                            st.session_state["restore_extended_data"] = restore_data.get("extended_api_data", {})
                            st.session_state["restore_location_map"] = restore_data.get("location_map", {})
                            ShowRestorePreview()
                            st.success("✅ Snapshot loaded for restore.")
                        except Exception as e:
                            st.error(f"❌ Failed to parse snapshot: {e}")
            
            #with st.expander("➕ Configure Rule", expanded=True):
            if operation_mode in ["Add", "Copy", "Replace"]:
                st.markdown("----")

                # --- Prepopulate data if a rule is selected in sidebar ---
                rule_prepopulate = {}
                if operation_mode in ["Add", "Replace"]:
                    selected_filter_rule = selected_rule if operation_mode in ["Copy", "Replace"] else st.session_state.get("copied_rule_key") or st.session_state.get("selected_rule_key")

                else:
                    selected_filter_rule = selected_rule if operation_mode == "Copy" else st.session_state.get("selected_rule_key")
                
                if selected_filter_rule and " - " in selected_filter_rule:
                    policy_part, comment_part = selected_filter_rule.split(" - ", 1)

                    rule_src = None
                    source_loc = st.session_state.get("copied_rule_location") if operation_mode == "Add" else None
                    candidate_locations = [source_loc] if source_loc else selected_locations

                    
                    for loc in candidate_locations:  # include all locations, not just selected

                        if loc == "VPN":
                            rules = st.session_state.get("rules_data", [])
                        else:
                            net_id = network_map.get(loc)
                            rules = network_details.get(net_id, {}).get("firewall_rules", [])
                        for r in rules:
                            if (
                                r.get("policy", "").strip().lower() == policy_part.strip().lower()
                                and r.get("comment", "").strip().lower() == comment_part.strip().lower()
                            ):
                                rule_src = r
                                break

                        if rule_src:
                            break
                    if rule_src:
                        rule_prepopulate = rule_src
                def cid_to_name(cid):
                    cid = cid.strip()
                    if cid.startswith("OBJ(") and cid[4:-1] in object_map.values():
                        return next((k for k, v in object_map.items() if v == cid[4:-1]), cid)
                    elif cid.startswith("GRP(") and cid[4:-1] in group_map.values():
                        return next((k for k, v in group_map.items() if v == cid[4:-1]), cid)
                    return cid
                col1, col2, col3, col4, col5, col6, col7  = st.columns([1, 5, 5, 1, 5, 1, 1])
                with col1:
                    action = st.selectbox("Action", ["allow", "deny"], index=0 if rule_prepopulate.get("policy", "").lower() != "deny" else 1)
                with col2:
                    new_comment = st.text_input("Comment", value=rule_prepopulate.get("comment", "New rule"))
                with col3:
                    src_values = rule_prepopulate.get("srcCidr", "Any").split(",")
                    src_named_default = [cid_to_name(cid) for cid in src_values if cid_to_name(cid) in all_options]
                    src_extra = ", ".join([cid for cid in src_values if cid_to_name(cid) not in all_options])
                    src_named = st.multiselect("🔍 Source Objects/Groups", all_options, default=src_named_default, key="src_named")
                    src_cidrs = st.text_input("✍️ Extra Source CIDRs (comma-separated)", value=src_extra, key="src_cidrs")
                    src_input = src_named + [x.strip() for x in src_cidrs.split(",") if x.strip()]
                with col4:
                    src_port = st.text_input("Source Port", value=rule_prepopulate.get("srcPort", "Any"))
                with col5:
                    dst_values = rule_prepopulate.get("destCidr", "Any").split(",")
                    dst_named_default = [cid_to_name(cid) for cid in dst_values if cid_to_name(cid) in all_options]
                    dst_extra = ", ".join([cid for cid in dst_values if cid_to_name(cid) not in all_options]) 
                    dst_named = st.multiselect("🔍 Destination Objects/Groups", all_options, default=dst_named_default, key="dst_named")
                    dst_cidrs = st.text_input("✍️ Extra Destination CIDRs (comma-separated)", value=dst_extra, key="dst_cidrs")
                    dst_input = dst_named + [x.strip() for x in dst_cidrs.split(",") if x.strip()]   
                with col6:
                    dst_port = st.text_input("Destination Port", value=rule_prepopulate.get("destPort", "Any"))
                with col7:
                    protocol = st.text_input("Protocol", value=rule_prepopulate.get("protocol", "tcp"))
        with st.container():
            if operation_mode in ["Add", "Delete", "Copy", "Replace"]:
                button_label = {
                    "Add": "➕ Add Rule",
                    "Delete": "🗑️ Delete Rule",
                    "Copy": "🗐 Copy Rule",
                    "Replace": "🔄 Replace Rule"
                    
                }.get(operation_mode, "➕ Update")

                if st.button(button_label):
                    
                    st.session_state["show_table"] = False
                    st.session_state["Deploy_Checked"] = False
                    if operation_mode == "Add":
                        if not src_input or not dst_input:
                            st.warning("Source and Destination cannot be empty.")
                        else:
                            new_rule = {
                                "policy": action,
                                "protocol": protocol,
                                "srcPort": src_port,
                                "destPort": dst_port,
                                "srcCidr": ",".join(f"OBJ({object_map[x]})" if x in object_map else f"GRP({group_map[x]})" if x in group_map else x for x in src_input),
                                "destCidr": ",".join(f"OBJ({object_map[x]})" if x in object_map else f"GRP({group_map[x]})" if x in group_map else x for x in dst_input),
                                "comment": new_comment,
                                "syslogEnabled": loc == "VPN"
                            }
                            ShowRulesPreview(new_rule, match_comment, match_policy, new_comment, action, insert_position, delete_rule=False)
                    elif operation_mode == "Delete" and match_comment:
                        ShowRulesPreview(None, match_comment, match_policy, "", "", None, delete_rule=True)

                    elif operation_mode == "Replace" and match_comment:
                        if not src_input or not dst_input:
                            st.warning("Source and Destination cannot be empty.")
                        else:
                            updated_rule = {
                                "policy": action,
                                "protocol": protocol,
                                "srcPort": src_port,
                                "destPort": dst_port,
                                "srcCidr": ",".join(f"OBJ({object_map[x]})" if x in object_map else f"GRP({group_map[x]})" if x in group_map else x for x in src_input),
                                "destCidr": ",".join(f"OBJ({object_map[x]})" if x in object_map else f"GRP({group_map[x]})" if x in group_map else x for x in dst_input),
                                "comment": new_comment,
                                "syslogEnabled": loc == "VPN"
                            }

                            for loc in selected_locations:
                                is_vpn = loc == "VPN"
                                rule_list = copy.deepcopy(
                                    st.session_state["preview_tables"].get(loc, st.session_state.get("rules_data", [])) if is_vpn
                                    else st.session_state["preview_tables"].get(loc, network_details[network_map.get(loc)].get("firewall_rules", []))
                                )

                                # Replace rule
                                for i, r in enumerate(rule_list):
                                    if r.get("comment", "") == match_comment and r.get("policy", "").lower() == match_policy.lower():
                                        rule_list[i] = updated_rule
                                        break

                                if is_vpn:
                                    st.session_state["preview_tables"]["VPN"] = rule_list
                                else:
                                    st.session_state["preview_tables"][loc] = rule_list


        # --- Preview Table for the Rule Being Built or Selected for Deletion ---
        preview_row = None

        if operation_mode in ["Add", "Copy", "Replace"]:
            try:
                preview_row = {
                    "Policy": action.upper(),
                    "Comment": new_comment,
                    "Source": ", ".join(src_input),
                    "Source Port": src_port,
                    "Destination": ", ".join(dst_input),
                    "Destination Port": dst_port,
                    "Protocol": protocol,
                    "is_new": True,
                    "is_deleted": False,
                }
            except Exception as e:
                st.error(f"Error building preview: {e}")

        elif operation_mode == "Delete" and match_comment:
            for loc in selected_locations:
                if loc == "VPN":
                    rules = st.session_state.get("rules_data", [])
                else:
                    net_id = network_map.get(loc)
                    rules = network_details.get(net_id, {}).get("firewall_rules", [])
                for r in rules:
                    if r.get("comment") == match_comment and r.get("policy", "").lower() == match_policy.lower():
                        preview_row = {
                            "Policy": r.get("policy", "").upper(),
                            "Comment": r.get("comment", ""),
                            "Source": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r.get("srcCidr", "").split(",")),
                            "Source Port": r.get("srcPort", ""),
                            "Destination": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r.get("destCidr", "").split(",")),
                            "Destination Port": r.get("destPort", ""),
                            "Protocol": r.get("protocol", ""),
                            "is_new": False,
                            "is_deleted": True,
                        }
                        break
                if preview_row:
                    break
        
        elif operation_mode == "Backup":
            backup_locations = st.session_state.get("selected_locations", [])
            extended_data = st.session_state.get("extended_data", {}).get("network_details", {})
            vpn_rules = st.session_state.get("rules_data", [])
 
            for loc in backup_locations:
                if loc == "VPN":
                    rule_set = rules_data
                else:
                    net_id = network_map.get(loc)

                    rule_set = fetch_updated_rules_for_location(network_id, base_url, headers)
                    
                if not rule_set:
                    continue
                if rule_set:
                    df_preview = pd.DataFrame(rule_set)
                    gb_preview = GridOptionsBuilder.from_dataframe(df_preview)
                    gb_preview.configure_default_column(filter=True, sortable=True, resizable=True, wrapText=True, autoHeight=True)
                    gb_preview.configure_grid_options(domLayout="autoHeight", getRowStyle=JsCode("""
                        function(params) {
                            if (params.data.Policy === "ALLOW") {
                                return {
                                    backgroundColor: '#99E2B4',
                                    color: '#155724',
                                    fontWeight: 'bold'
                                };
                            }
                            if (params.data.Policy === "DENY") {
                                return {
                                    backgroundColor: '#F7EF81',
                                    color: '#721c24',
                                    fontWeight: 'bold'
                                };
                            }
                            return {};
                        }
                    """))
                    json_data = json.dumps(rule_set, indent=2)
                    st.download_button(
                        label=(f"📥 Download Rules for `{loc}` as JSON"),
                        data=json_data,
                        file_name=f"{loc}_rules.json",
                        mime="application/json"
                        )
                    with st.expander(f"📁 View Rules for `{loc}`", expanded=False):
                        
                        AgGrid(
                            df_preview, 
                            gridOptions=gb_preview.build(), 
                            enable_enterprise_modules=False,
                            fit_columns_on_grid_load=True,
                            use_container_width=True,
                            allow_unsafe_jscode=True,
                            key=f"Backup_preview_{loc}")    

            # Snapshot download button
            
        elif operation_mode == "Use Template":
            restore_locations = st.session_state.get("selected_locations", [])
            if "restore_rules_data" not in st.session_state:
                st.session_state["restore_rules_data"] = []

            restore_data = st.session_state["restore_rules_data"]

            
            rule_set = restore_data

            with st.expander("📁 Template Rules", expanded=True):
                df_preview = pd.DataFrame([
                    {
                    "Rule Index": idx,   
                    "Policy": r.get("policy", "").upper(),
                    "Comment": r.get("comment", ""),
                    "Source": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r["srcCidr"].split(",")),
                    "Source Port": r.get("srcPort", ""),
                    "Destination": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r["destCidr"].split(",")),
                    "Destination Port": r.get("destPort", ""),
                    "Protocol": r.get("protocol", ""),
                    }
                    for idx, r in enumerate(rule_set)
                ])
                 
                gb_preview = GridOptionsBuilder.from_dataframe(df_preview)
                gb_preview.configure_default_column(filter=True, sortable=True, resizable=True, wrapText=True, autoHeight=True)
                gb_preview.configure_grid_options(domLayout="autoHeight", getRowStyle=JsCode("""
                    function(params) {
                        if (params.data.Policy === "ALLOW") {
                            return {
                                backgroundColor: '#99E2B4',
                                color: '#155724',
                                fontWeight: 'bold'
                            };
                        }
                        if (params.data.Policy === "DENY") {
                            return {
                                backgroundColor: '#F7EF81',
                                color: '#721c24',
                                fontWeight: 'bold'
                            };
                        }
                        return {};
                    }
                """))
                AgGrid(
                    df_preview, 
                    gridOptions=gb_preview.build(), 
                    enable_enterprise_modules=False,
                    fit_columns_on_grid_load=True,
                    use_container_width=True,
                    allow_unsafe_jscode=True,
                    key=f"Template_preview")
            
            if st.button("☑️ Aply Template to selected Locations"):
                for loc in restore_locations:
                    rules = rule_set
                    
                if loc == "VPN":
                    st.warning("VPN rules are not supported for this operation.")
                else:
                    st.session_state["current_selected_locations"] = sorted(restore_locations)
                    st.session_state["rule_type"] = "Local"
                    st.session_state["preview_tables"][loc] = rules
                    st.session_state["show_table"] = True
                    st.session_state["force_show_all_rules"] = True
                    st.session_state["Restore_done"] = True
                    st.session_state["Deploy_Checked"] = False   

        elif operation_mode == "Restore":
            restore_locations = st.session_state.get("selected_locations", [])
            restore_data = st.session_state.get("restore_extended_data", {}).get("network_details", {})
            vpn_rules = st.session_state.get("restore_rules_data", [])

            for loc in restore_locations:
                if loc == "VPN":
                    rule_set = vpn_rules
                else:
                    net_id = network_map.get(loc)
                    rule_set = restore_data.get(net_id, {}).get("firewall_rules", [])
                if not rule_set:
                    continue
                if not st.session_state.get("Restore_done", False):
                    

                    df = pd.DataFrame([
                        {
                        "Rule Index": idx,
                        "Policy": r.get("policy", "").upper(),
                        "Comment": r.get("comment", ""),
                        "Source": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r["srcCidr"].split(",")),
                        "Source Port": r.get("srcPort", ""),
                        "Destination": ", ".join(id_to_name(cid.strip(), object_map, group_map) for cid in r["destCidr"].split(",")),
                        "Destination Port": r.get("destPort", ""),
                        "Protocol": r.get("protocol", ""),
                        }
                        for idx, r in enumerate(rule_set)
                    ])
                    

                    gb_preview = GridOptionsBuilder.from_dataframe(df)
                    gb_preview.configure_default_column(filter=True, sortable=True, resizable=True, wrapText=True, autoHeight=True)
                    gb_preview.configure_grid_options(domLayout="autoHeight", getRowStyle=JsCode("""
                        function(params) {
                            if (params.data.Policy === "ALLOW") {
                                return {
                                    backgroundColor: '#99E2B4',
                                    color: '#155724',
                                    fontWeight: 'bold'
                                };
                            }
                            if (params.data.Policy === "DENY") {
                                return {
                                    backgroundColor: '#F7EF81',
                                    color: '#721c24',
                                    fontWeight: 'bold'
                                };
                            }
                            return {};
                        }
                    """))
                    st.markdown(f"🔎 **Preview of the Rule to Be Applied for '{loc}':**")
                    AgGrid(
                        df, 
                        gridOptions=gb_preview.build(), 
                        enable_enterprise_modules=False,
                        fit_columns_on_grid_load=True,
                        use_container_width=True,
                        allow_unsafe_jscode=True,
                        key=f"restore_preview_{loc}")
                

            # Make preview_tables from restore data
            if st.button("☑️ Load Restore Rules for Deployment"):
                for loc in restore_locations:
                    if loc == "VPN":
                        st.session_state["preview_tables"]["VPN"] = copy.deepcopy(vpn_rules)
                    else:
                        net_id = network_map.get(loc)
                        rules = restore_data.get(net_id, {}).get("firewall_rules", [])
                        st.session_state["preview_tables"][loc] = copy.deepcopy(rules)
                st.session_state["current_selected_locations"] = sorted(restore_locations)
                st.session_state["show_table"] = True
                st.session_state["force_show_all_rules"] = True
                st.session_state["Restore_done"] = True
                st.session_state["Deploy_Checked"] = False
                #st.rerun()

        # --- Show Preview of the Rule Being Built or Selected for Deletion ---
        # Show the preview row if available
        if preview_row:
            df_preview = pd.DataFrame([preview_row])
            gb_preview = GridOptionsBuilder.from_dataframe(df_preview)
            gb_preview.configure_default_column(filter=True, sortable=True, resizable=True, wrapText=True, autoHeight=True)
            gb_preview.configure_grid_options(domLayout="autoHeight", getRowStyle=JsCode("""
                function(params) {
                    if (params.data.Policy === "ALLOW") {
                        return {
                            backgroundColor: '#99E2B4',
                            color: '#155724',
                            fontWeight: 'bold'
                        };
                    }
                    if (params.data.Policy === "DENY") {
                        return {
                            backgroundColor: '#F7EF81',
                            color: '#721c24',
                            fontWeight: 'bold'
                        };
                    }
                    return {};
                }
            """))
            st.markdown("🔎 **Preview of the Rule to Be Applied:**")
            AgGrid(
                df_preview, 
                gridOptions=gb_preview.build(), 
                enable_enterprise_modules=False,
                fit_columns_on_grid_load=True,
                use_container_width=True,
                allow_unsafe_jscode=True,
                key=f"rule_preview")
                


        # Show/Hide
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("🔍 Show Rules"):
                st.session_state["show_table"] = True
        with col2:
            if st.button("❌ Hide Rules"):
                st.session_state["show_table"] = False
        

        # Render preview if flagged
        if st.session_state["show_table"]:
            ShowRulesPreview(None, "", "", "", "", insert_position)
    else:
        st.warning("Please load the data.")

elif selected_tab == "📟 LAN Reports":
    devices_data = st.session_state.get("devices_data", [])
    extended_data = st.session_state.get("extended_data", {})
    network_map = extended_data.get("network_map", {})
    network_details = extended_data.get("network_details", {})

    id_to_name = {v: k for k, v in network_map.items() if v}
    switches = [
        d for d in devices_data
        if d.get("productType", "").lower() == "switch" and d.get("networkId") in id_to_name
    ]
    all_locations = sorted(set(id_to_name[d["networkId"]] for d in switches))


    with st.expander("📈 Daily Open Port Totals"):
        #st.subheader("📈 Daily Open Port Totals")
        df_totals = load_totals_from_comparisons()
        if not df_totals.empty:
            df_totals.sort_values("date", inplace=True)
            df_totals["date"] = pd.to_datetime(df_totals["date"])  # Ensure proper date format

            chart = alt.Chart(df_totals).mark_line(point=True).encode(
                x=alt.X("date:T", title="Date", axis=alt.Axis(format="%Y-%m-%d", labelAngle=-45)),
                y=alt.Y("total:Q", scale=alt.Scale(zero=False), title="Open Ports Total"),
                tooltip=["date:T", "total:Q"]
            ).properties(
                #title="📈 Daily Open Port Totals",
                width=800,
                height=400
            )

            st.altair_chart(chart, use_container_width=True)
        else:
            st.info("No report data found.")




    with st.sidebar:
        location_filter_title = f"📍 Location Filter ({len(switches)} switches found)"
        st.session_state.setdefault("selected_dot1x_locations", all_locations)

        with st.expander(location_filter_title, expanded=True):
            if st.button("✅ Select All", key="dot1x_select_all"):
                st.session_state["selected_dot1x_locations"] = all_locations
            if st.button("❌ Deselect All", key="dot1x_deselect_all"):
                st.session_state["selected_dot1x_locations"] = []

            valid_selected = [
                loc for loc in st.session_state.get("selected_dot1x_locations", [])
                if loc in all_locations
            ]
            st.session_state["selected_dot1x_locations"] = valid_selected

            st.multiselect(
                "Pick location(s)",
                options=all_locations,
                key="selected_dot1x_locations"
            )

            selected_locations = st.session_state["selected_dot1x_locations"]

        trigger_dot1x = st.button("🔍 Dot1x Report")

        uploaded = st.file_uploader("📤 Upload Previous Dot1x Report (CSV)", type="csv", key="dot1x_upload")
        if uploaded:
            st.session_state["dot1x_uploaded_csv"] = uploaded
            try:
                df_uploaded = pd.read_csv(uploaded)
                if isinstance(df_uploaded, pd.DataFrame):
                    st.session_state["uploaded_df"] = df_uploaded
            except Exception as e:
                st.error(f"Error reading uploaded Dot1x CSV: {e}")
        else:
            st.session_state["uploaded_df"] = [] 

        trigger_trunk = st.button("🔍 Trunk Report")
        if trigger_trunk:
            st.session_state["trunk_report_df"] = pd.DataFrame(columns=["networkname", "portid"])
            st.session_state["tr_uploaded_df"] = pd.DataFrame(columns=["networkname", "portid"])

        tr_uploaded = st.file_uploader("📤 Upload Previous Trunk Report (CSV)", type="csv", key="trunk_upload")
        if tr_uploaded:
            st.session_state["trunk_uploaded_csv"] = tr_uploaded
            try:
                df_tr_uploaded = pd.read_csv(tr_uploaded)
                if isinstance(df_tr_uploaded, pd.DataFrame):
                    st.session_state["tr_uploaded_df"] = df_tr_uploaded
            except Exception as e:
                st.error(f"Error reading uploaded Trunk CSV: {e}")
        else:
            st.session_state["tr_uploaded_df"] =[]


    if selected_locations:
        selected_net_ids = [network_map.get(loc) for loc in selected_locations]
        sw_expanded = True
        # Filter switches robustly by networkId and switch type/model
        switches = [
            d for d in devices_data
            if d.get("networkId") in selected_net_ids and (
                d.get("productType", "").lower() == "switch"
            )
        ]
        rows = len(switches)
        row_height = 35  # Approximate row height in pixels
        max_height = 2000
        min_height = 150
        dynamic_height = min(max(rows * row_height, min_height), max_height)
        # Build and show switch table
        with st.expander("### 📟 Switches in Selected Location(s)", expanded = sw_expanded):
            if switches:
                switch_table = pd.DataFrame([
                    {
                        "NetworkName": next((name for name, nid in network_map.items() if nid == d.get("networkId")), "—"),
                        "Device Name": d.get("name", "—"),
                        "Type": d.get("productType", "-"),
                        "Model": d.get("model", "—"),
                        "Serial": d.get("serial", "—"),
                        "url": d.get("url", "-")
                    }
                    for d in switches
                ])

                switch_html_rows = ""
                for _, row in switch_table.iterrows():
                    serial_link = (
                        f'<a href="{row["url"]}" target="_blank">{row["Serial"]}</a>'
                        if row["url"] not in ("-", "—") else row["Serial"]
                    )
                    switch_html_rows += f"""
                        <tr style="border: 1px solid #ccc;">
                            <tr style="border: 1px solid #ccc;">
                            <td>{row["NetworkName"]}</td>
                            <td>{row["Device Name"]}</td>
                            <td>{row["Model"]}</td>
                            <td>{serial_link}</td>
                        </tr>
                    """

                # Full HTML table with borders
                switch_html = f"""
                <div style="overflow-x:auto;">
                    <table style="width:100%; border-collapse: collapse; font-family: sans-serif; border: 1px solid #ccc;">
                        <thead>
                            <tr style="background-color: #f2f2f2; border: 1px solid #ccc;">
                                <th style="border: 1px solid #ccc; padding: 8px;">NetworkName</th>
                                <th style="border: 1px solid #ccc; padding: 8px;">Device Name</th>
                                <th style="border: 1px solid #ccc; padding: 8px;">Model</th>
                                <th style="border: 1px solid #ccc; padding: 8px;">Serial</th>
                            </tr>
                        </thead>
                        <tbody>
                            {switch_html_rows}
                        </tbody>
                    </table>
                </div>
                """

                #st.markdown("### 📟 Switches in Selected Location(s)")
                components.html(switch_html, height=dynamic_height, scrolling=True)
            else:
                st.info("No switches found for the selected location(s).")

    port_data = []

    if trigger_dot1x or trigger_trunk:
        sw_expanded = False
        st.info("Fetching port data from switches...")
        headers = st.session_state.get("headers")
        base_url = st.session_state.get("base_url", "https://api.meraki.com/api/v1")

        for switch in switches:
            serial = switch["serial"]
            device_name = switch.get("name", "Unknown")
            net_id = switch.get("networkId")
            net_name = next((v["network_name"] for k, v in network_details.items() if k == net_id), "")

            url = f"{base_url}/devices/{serial}/switch/ports"
            try:
                resp = requests.get(url, headers=headers)
                resp.raise_for_status()
                ports = resp.json()

                for port in ports:
                    if trigger_dot1x and port.get("accessPolicyType") == "Open" and port.get("type") in ("access", "trunk") and port.get("enabled"):
                        port_data.append({
                            "NetworkID": net_id,
                            "NetworkName": net_name,
                            "Serial": serial,
                            "DeviceName": device_name,
                            "portId": port.get("portId"),
                            "name": port.get("name", ""),
                            "enabled": port.get("enabled"),
                            "type": port.get("type"),
                            "vlan": port.get("vlan"),
                            "voiceVlan": port.get("voiceVlan"),
                            "allowedVlans": port.get("allowedVlans"),
                            "accessPolicyType": port.get("accessPolicyType"),
                            "accessPolicyNumber": port.get("accessPolicyNumber"),
                            "Link": switch.get("url", "-")
                        })
                    if trigger_trunk and port.get("type") == "trunk":
                        port_data.append({
                            "NetworkID": net_id,
                            "NetworkName": net_name,
                            "Serial": serial,
                            "DeviceName": device_name,
                            "portId": port.get("portId"),
                            "name": port.get("name", ""),
                            "enabled": port.get("enabled"),
                            "vlan": port.get("vlan"),
                            "allowedVlans": port.get("allowedVlans"),
                            "Link": switch.get("url", "-")
                        })
            except requests.RequestException as e:
                st.error(f"Failed to fetch ports for {device_name}: {e}")
        
    if port_data:
        df = pd.DataFrame(port_data)
        rows = len(df)
        locations = len(selected_locations)
        row_height = 35  # Approximate row height in pixels
        max_height = 2000
        min_height = 150
        dynamic_height = min(max(rows * row_height, min_height), max_height)
        rp_expanded = not sw_expanded
        with st.expander("Current Report", expanded = rp_expanded):
            if trigger_dot1x:
                st.markdown(f"Showing {rows} open ports for {locations} locations")
                st.dataframe(df, use_container_width=True, height=dynamic_height)
                st.session_state["dot1x_report_df"] = df
                st.session_state["ready_for_upload"] = True
                st.download_button("📥 Download Dot1x Report (CSV)", df.to_csv(index=False), file_name="dot1x_report.csv", mime="text/csv") 

                st.session_state.pop("trunk_report_df", None)
                st.session_state.pop("tr_uploaded_df", None)
                st.session_state.pop("trunk_uploaded_csv", None)

            if trigger_trunk:
                st.markdown(f"Showing {rows} trunk ports for {locations} locations")
                st.dataframe(df, use_container_width=True, height=dynamic_height)
                st.session_state["trunk_report_df"] = df
                st.download_button("📥 Download Trunks Report (CSV)", df.to_csv(index=False), file_name="trunks_report.csv", mime="text/csv") 

                st.session_state.pop("dot1x_report_df", None)
                st.session_state.pop("uploaded_df", None)
                st.session_state.pop("dot1x_uploaded_csv", None)

    else:
        st.warning("No port data retrieved.")


            # Show uploaded report, if present
    if "uploaded_df" in st.session_state and trigger_dot1x:

        st.session_state.pop("trunk_report_df", None)
        st.session_state.pop("tr_uploaded_df", None)
        st.session_state.pop("trunk_uploaded_csv", None)

        uploaded_df = st.session_state["uploaded_df"]
        if isinstance(uploaded_df, pd.DataFrame):
            uploaded_df.columns = uploaded_df.columns.str.strip().str.lower()

            rows = len(uploaded_df)
            row_height = 35
            max_height = 2000
            min_height = 150
            dynamic_height = min(max(rows * row_height, min_height), max_height)

            with st.expander("📄 Uploaded Dot1x Report"):
                st.dataframe(uploaded_df, use_container_width=True, height=dynamic_height)


    if "tr_uploaded_df" in st.session_state and trigger_trunk:

        st.session_state.pop("dot1x_report_df", None)
        st.session_state.pop("uploaded_df", None)
        st.session_state.pop("dot1x_uploaded_csv", None)

        tr_uploaded_df = st.session_state["tr_uploaded_df"]
        if isinstance(tr_uploaded_df, pd.DataFrame):
            tr_uploaded_df.columns = tr_uploaded_df.columns.str.strip().str.lower()

            rows = len(tr_uploaded_df)
            row_height = 35
            max_height = 2000
            min_height = 150
            dynamic_height = min(max(rows * row_height, min_height), max_height)

            with st.expander("📄 Uploaded Trunks Report"):
                st.dataframe(tr_uploaded_df, use_container_width=True, height=dynamic_height)

    # Step 2: Run comparison only when both reports are present
    if "dot1x_report_df" in st.session_state and trigger_dot1x:
        current_df = st.session_state["dot1x_report_df"]

        # Use uploaded or fallback initial file
        if "uploaded_df" in st.session_state and isinstance(st.session_state["uploaded_df"], pd.DataFrame):
            uploaded_df = st.session_state["uploaded_df"]
        else:
            try:
                uploaded_df = pd.read_csv("dot1x_initial.csv")
                st.success("Loaded Initial Report")
            except Exception as e:
                st.error(f"Cannot load fallback dot1x_initial.csv: {e}")
                uploaded_df = pd.DataFrame(columns=["networkname", "portid", "type"])

        current_df.columns = current_df.columns.str.strip().str.lower()
        uploaded_df.columns = uploaded_df.columns.str.strip().str.lower()
        current_df["networkname"] = current_df["networkname"].str.strip().str.lower()
        uploaded_df["networkname"] = uploaded_df["networkname"].str.strip().str.lower()

        current_df = current_df[current_df["networkname"].isin([loc.lower() for loc in selected_locations])]
        uploaded_df = uploaded_df[uploaded_df["networkname"].isin([loc.lower() for loc in selected_locations])]


        # Current summary
        current_summary = current_df.groupby("networkname")["portid"].count().reset_index(name="current_total")

        current_summary["current_trunk"] = (
            current_df[current_df["type"] == "trunk"]
            .groupby("networkname")["portid"].count()
            .reindex(current_summary["networkname"])
            .fillna(0).astype(int).values
        )
        current_summary["current_access_type"] = (
            current_df[current_df["type"] == "access"]
            .groupby("networkname")["portid"].count()
            .reindex(current_summary["networkname"])
            .fillna(0).astype(int).values
        )


        # Previous summary
        previous_summary = uploaded_df.groupby("networkname")["portid"].count().reset_index(name="previous_total")

        previous_summary["previous_trunk"] = (
            uploaded_df[uploaded_df["type"] == "trunk"]
            .groupby("networkname")["portid"].count()
            .reindex(previous_summary["networkname"])
            .fillna(0).astype(int).values
        )
        previous_summary["previous_access_type"] = (
            uploaded_df[uploaded_df["type"] == "access"]
            .groupby("networkname")["portid"].count()
            .reindex(previous_summary["networkname"])
            .fillna(0).astype(int).values
        )

        # Merge and compute diffs
        comparison = pd.merge(current_summary, previous_summary, on="networkname", how="outer").fillna(0)
        cols_to_int = [col for col in comparison.columns if col != "networkname"]
        comparison[cols_to_int] = comparison[cols_to_int].astype(int)

        comparison["diff_total"] = comparison["current_total"] - comparison["previous_total"]
        comparison["diff_access_type"] = comparison["current_access_type"] - comparison["previous_access_type"]
        comparison["diff_trunk"] = comparison["current_trunk"] - comparison["previous_trunk"]

        # Highlight style
        def highlight_color(val):
            return "background-color: #c6f6d5" if val < 0 else "background-color: #fed7d7" if val > 0 else ""

        diff_cols = ["diff_access_type", "diff_trunk", "diff_total"]

        styled_df = comparison[[
            "networkname",
            "current_access_type", "diff_access_type",
            "current_trunk", "diff_trunk",
            "current_total", "diff_total"
        ]].style.applymap(highlight_color, subset=diff_cols)

        
        # Append summary row
        summary_data = {col: comparison[col].sum() for col in cols_to_int}
        summary_data["networkname"] = "TOTAL"
        summary_data["diff_total"] = summary_data["current_total"] - summary_data["previous_total"]
        summary_data["diff_access_type"] = summary_data["current_access_type"] - summary_data["previous_access_type"]
        summary_data["diff_trunk"] = summary_data["current_trunk"] - summary_data["previous_trunk"]

        # Convert all to int
        for col in cols_to_int + ["diff_total", "diff_access_type", "diff_trunk"]:
            summary_data[col] = int(summary_data.get(col, 0))

        comparison_with_total = pd.concat([comparison, pd.DataFrame([summary_data])], ignore_index=True)

        styled_df = comparison_with_total[[
            "networkname",
            "current_access_type", "diff_access_type",
            "current_trunk", "diff_trunk",
            "current_total", "diff_total"
        ]].style.applymap(highlight_color, subset=diff_cols)

        st.markdown("### 📊 Dot1x Report Comparison vs 06.06.2025")
        st.dataframe(styled_df, use_container_width=True)



    if trigger_trunk:
        current_df = st.session_state.get("trunk_report_df", pd.DataFrame(columns=["networkname", "portid"]))

        # Use uploaded or fallback initial file
        if "tr_uploaded_df" in st.session_state and isinstance(st.session_state["tr_uploaded_df"], pd.DataFrame):
            uploaded_df = st.session_state["tr_uploaded_df"]
        else:
            try:
                uploaded_df = pd.read_csv("trunk_initial.csv")
                st.success("Loaded Initial Report")
            except Exception as e:
                st.error(f"Cannot load fallback trunk_initial.csv: {e}")
                uploaded_df = pd.DataFrame(columns=["networkname", "portid"])

        current_df.columns = current_df.columns.str.strip().str.lower()
        uploaded_df.columns = uploaded_df.columns.str.strip().str.lower()
        current_df["networkname"] = current_df["networkname"].astype(str).str.strip().str.lower()
        uploaded_df["networkname"] = uploaded_df["networkname"].astype(str).str.strip().str.lower()

        current_df = current_df[current_df["networkname"].isin([loc.lower() for loc in selected_locations])]
        uploaded_df = uploaded_df[uploaded_df["networkname"].isin([loc.lower() for loc in selected_locations])]


        # Ensure portid is numeric and drop invalid rows
        current_df["portid"] = pd.to_numeric(current_df["portid"], errors="coerce")
        uploaded_df["portid"] = pd.to_numeric(uploaded_df["portid"], errors="coerce")
        current_df = current_df.dropna(subset=["portid"])
        uploaded_df = uploaded_df.dropna(subset=["portid"])

        # Group and aggregate
        current_summary = current_df.groupby("networkname").agg(current_total=("portid", "count")).reset_index()
        previous_summary = uploaded_df.groupby("networkname").agg(previous_total=("portid", "count")).reset_index()

        # Merge summaries
        comparison = pd.merge(current_summary, previous_summary, on="networkname", how="outer").fillna(0)
        comparison["current_total"] = comparison["current_total"].astype(int)
        comparison["previous_total"] = comparison["previous_total"].astype(int)
        comparison["diff_total"] = comparison["current_total"] - comparison["previous_total"]

        # Highlight delta
        def highlight_trunk(val):
            return "background-color: #c6f6d5" if val < 0 else "background-color: #fed7d7" if val > 0 else ""

        styled_trunk_df = comparison.style.applymap(highlight_trunk, subset=["diff_total"])

        
        # Append summary row
        summary_data = {
            "networkname": "TOTAL",
            "current_total": int(comparison["current_total"].sum()),
            "previous_total": int(comparison["previous_total"].sum())
        }
        summary_data["diff_total"] = summary_data["current_total"] - summary_data["previous_total"]

        comparison_with_total = pd.concat([comparison, pd.DataFrame([summary_data])], ignore_index=True)

        styled_trunk_df = comparison_with_total.style.applymap(highlight_trunk, subset=["diff_total"])

        st.markdown("### 📊 Trunk Report Comparison vs 25.05.2025")
        st.dataframe(styled_trunk_df, use_container_width=True)


if selected_tab == "🌐 VLAN Configuration !ADMIN!":

