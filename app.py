import streamlit as st
import pandas as pd
import requests
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
from streamlit_searchbox import st_searchbox
from utils.file_loader import load_json_file
from utils.helpers import safe_dataframe, get_object_map, get_group_map, id_to_name
from utils.match_logic import resolve_to_cidrs, match_input_to_rule, is_exact_subnet_match
from API_Calls import fetch_meraki_data

# ------------------ PAGE SETUP ------------------
st.set_page_config(page_title="Meraki VPN Rule Checker", layout="wide", page_icon="🛡️", initial_sidebar_state="expanded")

# ------------------ GLOBAL STATE INIT ------------------
if "rules_data" not in st.session_state:
    st.session_state["rules_data"] = None
if "objects_data" not in st.session_state:
    st.session_state["objects_data"] = None
if "groups_data" not in st.session_state:
    st.session_state["groups_data"] = None
if "source_raw_input" not in st.session_state:
    st.session_state["source_raw_input"] = ""
if "destination_raw_input" not in st.session_state:
    st.session_state["destination_raw_input"] = ""

# ------------------ API CALL HANDLING ------------------import streamlit as st
import pandas as pd
import requests
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
from utils.file_loader import safe_dataframe, get_object_map, get_group_map, id_to_name
from utils.match_logic import resolve_to_cidrs, match_input_to_rule, is_exact_subnet_match
from streamlit_searchbox import st_searchbox

# ------------------ PAGE SETUP ------------------
st.set_page_config(
    page_title="Meraki VPN Rule Checker",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# ------------------ SESSION STATE INIT ------------------
for key in ["source_raw_input", "destination_raw_input"]:
    if key not in st.session_state:
        st.session_state[key] = ""

# ------------------ API CONFIG ------------------
API_HEADERS = {
    "X-Cisco-Meraki-API-Key": st.secrets.get("API_KEY", ""),
    "Content-Type": "application/json",
    "X-Cisco-Meraki-Organization-ID": st.secrets.get("ORG_ID", "")
}
RULES_URL = "https://api.meraki.com/api/v1/organizations/{org_id}/appliance/vpn/vpnFirewallRules"
OBJECTS_URL = "https://api.meraki.com/api/v1/organizations/{org_id}/policyObjects"
GROUPS_URL = "https://api.meraki.com/api/v1/organizations/{org_id}/policyObjects/groups"

def fetch_meraki_data():
    try:
        rules_resp = requests.get(RULES_URL, headers=API_HEADERS)
        objects_resp = requests.get(OBJECTS_URL, headers=API_HEADERS)
        groups_resp = requests.get(GROUPS_URL, headers=API_HEADERS)

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

# ------------------ SIDEBAR DATA HANDLING ------------------
st.sidebar.header("🔧 Configuration")

if "rules_data" not in st.session_state or "object_map" not in st.session_state or "group_map" not in st.session_state:
    rules_data, objects_data, groups_data, fetched = fetch_meraki_data()
    if fetched:
        st.session_state["rules_data"] = rules_data
        st.session_state["objects_data"] = objects_data
        st.session_state["groups_data"] = groups_data
        st.session_state["object_map"] = get_object_map(objects_data)
        st.session_state["group_map"] = get_group_map(groups_data)
    else:
        st.warning("⚠️ Failed to load from API. Please upload files manually.")

# Manual override for Rules file
uploaded_rules_file = st.sidebar.file_uploader("📄 Upload Rules.json", type="json", key="rules_upload")
if uploaded_rules_file:
    st.session_state["rules_data"] = safe_dataframe(uploaded_rules_file)["rules"]

# Optional Refresh Button
if st.sidebar.button("🔄 Refresh API Data"):
    rules_data, objects_data, groups_data, fetched = fetch_meraki_data()
    if fetched:
        st.session_state["rules_data"] = rules_data
        st.session_state["objects_data"] = objects_data
        st.session_state["groups_data"] = groups_data
        st.session_state["object_map"] = get_object_map(objects_data)
        st.session_state["group_map"] = get_group_map(groups_data)
        st.success("✅ Data refreshed from Meraki API.")
    else:
        st.error("❌ Failed to refresh data from API.")

# Aliases
rules_data = st.session_state.get("rules_data", [])
objects_data = st.session_state.get("objects_data", [])
groups_data = st.session_state.get("groups_data", [])
object_map = st.session_state.get("object_map", {})
group_map = st.session_state.get("group_map", {})
# ------------------ UTILITY FUNCTIONS ------------------

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


# ------------------ SESSION STATE DEFAULTS ------------------
if "source_raw_input" not in st.session_state:
    st.session_state["source_raw_input"] = ""

if "destination_raw_input" not in st.session_state:
    st.session_state["destination_raw_input"] = ""
# ------------------ SIDEBAR COLOR TOOLBOX ------------------
st.sidebar.markdown("### 🎨 Highlight Color Settings")

def color_slider(label, default_hex):
    return st.sidebar.color_picker(label, value=default_hex)

highlight_colors = {
    "allow_exact": color_slider("Exact ALLOW", "#00cc44"),
    "deny_exact": color_slider("Exact DENY", "#cc0000"),
    "allow_partial": color_slider("Partial ALLOW", "#99e6b3"),
    "deny_partial": color_slider("Partial DENY", "#ff9999")
}

# Save colors in session state for access elsewhere
for key, color in highlight_colors.items():
    st.session_state[key] = color

# ------------------ TABS ------------------
tab4, tab1, tab2 = st.tabs(["🔎 Object Search", "🛡️ Rule Checker", "🧠 Optimization Insights"])
# ------------------ TAB 1: RULE CHECKER ------------------
with tab1:
    st.header("🛡️ Rule Checker")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        source_input = st_searchbox(
            search_objects_and_groups,
            placeholder="Search Source (Object, Group, or CIDR)",
            label="Source (SRC)",
            key="src_searchbox"
        ) or st.session_state.get("source_raw_input", "")
        st.session_state["source_raw_input"] = source_input

    with col2:
        source_port_input = st.text_input("Source Port(s)", "any")
    with col3:
        destination_input = st_searchbox(
            search_objects_and_groups,
            placeholder="Search Destination (Object, Group, or CIDR)",
            label="Destination (DST)",
            key="dst_searchbox"
        ) or st.session_state.get("destination_raw_input", "")
        st.session_state["destination_raw_input"] = destination_input

    with col4:
        port_input = st.text_input("Destination Port(s)", "443, 8080")

    protocol = st.selectbox("Protocol", ["any", "tcp", "udp", "icmpv4", "icmpv6"], index=0)
    filter_toggle = st.checkbox("Show only matching rules", value=False)

    source_cidrs = resolve_search_input(source_input)
    destination_cidrs = resolve_search_input(destination_input)

    skip_src_check = source_input.strip().lower() == "any"
    skip_dst_check = destination_input.strip().lower() == "any"
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

        src_match = True if skip_src_check else any(match_input_to_rule(resolved_src_cidrs, cidr) for cidr in source_cidrs)
        dst_match = True if skip_dst_check else any(match_input_to_rule(resolved_dst_cidrs, cidr) for cidr in destination_cidrs)
        proto_match = True if skip_proto_check else (rule_protocol == "any" or rule_protocol == protocol.lower())
        matched_ports_list = dports_to_loop if skip_dport_check else [p for p in dports_to_loop if p in rule_dports or "any" in rule_dports]
        matched_sports_list = source_port_input.split(",") if not skip_sport_check else ["any"]
        matched_sports_list = [p.strip() for p in matched_sports_list if p.strip() in rule_sports or "any" in rule_sports]
        sport_match = len(matched_sports_list) > 0
        port_match = len(matched_ports_list) > 0 and sport_match

        full_match = src_match and dst_match and proto_match and port_match

        exact_src = skip_src_check or all(
            any(is_exact_subnet_match(cidr, [rule_cidr]) for rule_cidr in resolved_src_cidrs)
            for cidr in source_cidrs
        )
        exact_dst = skip_dst_check or all(
            any(is_exact_subnet_match(cidr, [rule_cidr]) for rule_cidr in resolved_dst_cidrs)
            for cidr in destination_cidrs
        )
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
            "Rule Index": idx + 1,
            "Action": rule["policy"].upper(),
            "Comment": rule.get("comment", ""),
            "Source": ", ".join(source_names),
            "Source Port": rule.get("srcPort", ""),
            "Destination": ", ".join(dest_names),
            "Ports": rule["destPort"],
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
            backgroundColor: params.data.Action === "ALLOW" ? '{st.session_state["allow_exact"]}' : '{st.session_state["deny_exact"]}',
            color: 'white',
            fontWeight: 'bold'
        }};
    }}
    if (params.data["Partial Match 🔶"] === true) {{
        return {{
            backgroundColor: params.data.Action === "ALLOW" ? '{st.session_state["allow_partial"]}' : '{st.session_state["deny_partial"]}',
            fontWeight: 'bold'
        }};
    }}
    return {{}};
}}
""")

    gb = GridOptionsBuilder.from_dataframe(df_to_show)
    gb.configure_default_column(filter=True, sortable=True, resizable=True)
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
        allow_unsafe_jscode=True
    )
# ------------------ TAB 2: OPTIMIZATION INSIGHTS ------------------
with tab2:
    st.header("🧠 Optimization Insights")

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
                [i + 1]
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
                    f"⚠️ **Broad Rule Risk** at index {i + 1}: `{rule['policy'].upper()} ANY to ANY on ANY` — may shadow rules below.",
                    [i + 1]
                ))

        # Shadowed rule detection
        for j in range(i):
            if rule_covers(rules_data[j], rule):
                insight_rows.append((
                    f"🚫 **Shadowed Rule** at index {i + 1}: unreachable due to broader rule at index {j + 1}.",
                    [j + 1, i + 1]
                ))
                break

        # Merge opportunities
        if i < len(rules_data) - 1:
            next_rule = rules_data[i + 1]
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
| Term                 | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| 🔁 **Duplicate Rule** | Rule is identical to a previous one (all fields except comment)             |
| 🔄 **Merge Candidate**| Rules could be combined (only one field differs, e.g., port)                |
| ⚠️ **Broad Rule Risk**| `ANY` rule appears early and could shadow everything below                 |
| 🚫 **Shadowed Rule**  | Rule is never reached because an earlier rule already matches its traffic   |
""")
# ------------------ TAB 4: OBJECT & GROUP SEARCH ------------------
with tab4:
    st.header("🔎 Object & Group Search")

    search_term = st.text_input("Search by name or CIDR:", "").lower()

    def match_object(obj, term):
        return term in obj.get("name", "").lower() or term in obj.get("cidr", "").lower()

    filtered_objs = [o for o in objects_data if match_object(o, search_term)] if search_term else objects_data
    filtered_grps = [g for g in groups_data if search_term in g["name"].lower()] if search_term else groups_data

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

def try_fetch_data():
    try:
        rules, objects, groups = fetch_meraki_data()
        if all([rules, objects, groups]):
            st.session_state["rules_data"] = rules["rules"]
            st.session_state["objects_data"] = objects
            st.session_state["groups_data"] = groups
            st.session_state["api_success"] = True
        else:
            st.session_state["api_success"] = False
    except Exception as e:
        st.session_state["api_success"] = False
        st.error(f"API call failed: {e}")

# ------------------ SIDEBAR ------------------
st.sidebar.header("🔧 Configuration")

if "api_success" not in st.session_state:
    try_fetch_data()

if not st.session_state.get("api_success"):
    st.sidebar.info("API unavailable. Please upload files.")
    rules_file = st.sidebar.file_uploader("Rules.json", type="json")
    objects_file = st.sidebar.file_uploader("Objects.json", type="json")
    groups_file = st.sidebar.file_uploader("Groups.json", type="json")
    if all([rules_file, objects_file, groups_file]):
        st.session_state["rules_data"] = load_json_file(rules_file)["rules"]
        st.session_state["objects_data"] = load_json_file(objects_file)
        st.session_state["groups_data"] = load_json_file(groups_file)
else:
    st.sidebar.success("✅ API data loaded successfully.")
    if st.sidebar.button("🔄 Refresh Data"):
        try_fetch_data()

rules_data = st.session_state["rules_data"]
objects_data = st.session_state["objects_data"]
groups_data = st.session_state["groups_data"]

if not all([rules_data, objects_data, groups_data]):
    st.warning("No data available. Please check your API credentials or upload files.")
    st.stop()

object_map = get_object_map(objects_data)
group_map = get_group_map(groups_data)
# ------------------ SEARCH & RESOLUTION HELPERS ------------------
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

# ------------------ RULE CHECKER TAB ------------------
tab4, tab1, tab2 = st.tabs(["🔎 Object Search", "🛡️ Rule Checker", "🧠 Optimization Insights"])

# ------------------ RULE CHECKER TAB ------------------
with tab1:
    st.header("🛡️ Rule Checker")

    def custom_search(term: str):
        term = term.strip()
        results = []
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
        source_port_input = st.text_input("Source Port(s)", "any")
    with col3:
        destination_input = st_searchbox(
            custom_search,
            placeholder="Destination (Object, Group, CIDR, or 'any')",
            label="Destination (DST)",
            key="dst_searchbox",
            default="any"
        )
    with col4:
        port_input = st.text_input("Destination Port(s)", "any")
    
    with col5:
        protocol = st.selectbox("Protocol", ["any", "tcp", "udp", "icmpv4", "icmpv6"], index=0)
    
    col_left, col_right = st.columns(2)  

    with col_left:
        filter_toggle = st.checkbox("Show only matching rules", value=False)


    source_input = source_input or "any"
    destination_input = destination_input or "any"

    source_cidrs = resolve_search_input(source_input)
    destination_cidrs = resolve_search_input(destination_input)

    skip_src_check = source_input.strip().lower() == "any"
    skip_dst_check = destination_input.strip().lower() == "any"
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

        src_match = True if skip_src_check else any(match_input_to_rule(resolved_src_cidrs, cidr) for cidr in source_cidrs)
        dst_match = True if skip_dst_check else any(match_input_to_rule(resolved_dst_cidrs, cidr) for cidr in destination_cidrs)
        proto_match = True if skip_proto_check else (rule_protocol == "any" or rule_protocol == protocol.lower())
        matched_ports_list = dports_to_loop if skip_dport_check else [p for p in dports_to_loop if p in rule_dports or "any" in rule_dports]
        matched_sports_list = source_port_input.split(",") if not skip_sport_check else ["any"]
        matched_sports_list = [p.strip() for p in matched_sports_list if p.strip() in rule_sports or "any" in rule_sports]
        sport_match = len(matched_sports_list) > 0
        port_match = len(matched_ports_list) > 0 and sport_match

        full_match = src_match and dst_match and proto_match and port_match

        exact_src = ("Any" in rule["srcCidr"]) if skip_src_check else all(
            any(is_exact_subnet_match(cidr, [rule_cidr]) for rule_cidr in resolved_src_cidrs)
            for cidr in source_cidrs
        )

        exact_dst = ("Any" in rule["destCidr"]) if skip_dst_check else all(
            any(is_exact_subnet_match(cidr, [rule_cidr]) for rule_cidr in resolved_dst_cidrs)
            for cidr in destination_cidrs
        )

        exact_ports = skip_dport_check and rule["destPort"].lower() == "any" and rule.get("srcPort", "").lower() == "any"
        exact_proto = skip_proto_check and rule["protocol"].lower() == "any"
        
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
    gb.configure_grid_options(getRowStyle=row_style_js, domLayout='autoHeight')
    gb.configure_column("Comment",resizable=True, wrapText=True, autoHeight=True)
    gb.configure_column("Source",resizable=True, wrapText=True, autoHeight=True)
    gb.configure_column("Destination",resizable=True, wrapText=True, autoHeight=True)
    grid_options = gb.build()

    AgGrid(
        df_to_show,
        gridOptions=grid_options,
        enable_enterprise_modules=False,
        fit_columns_on_grid_load=True,
        use_container_width=True,
        allow_unsafe_jscode=True
    )

with tab2:
    st.header("🧠 Optimization Insights")

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


# ------------------ TAB 4: Object Search ------------------
with tab4:
    st.header("🔎 Object & Group Search")

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
