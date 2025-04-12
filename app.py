import streamlit as st
import pandas as pd
import ipaddress
import requests
import json
import base64
from io import BytesIO
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode
from streamlit_searchbox import st_searchbox
from helpers import (
    extract_keys_from_json,
    extract_network_names,
    is_valid_ipv4,
    parse_ports,
    parse_protocol,
    extract_port_ranges
)
from match_logic import (
    build_object_location_map,
    search_objects_and_groups,
    resolve_search_input,
    generate_port_match_flags,
    is_exact_subnet_match,
    get_networks_by_location,
    get_matching_locations_for_traffic,
    generate_rule_summary,
    resolve_to_cidrs
)
from API import fetch_meraki_data, fetch_meraki_data_extended
from file_loader import load_json_file, parse_uploaded_json

st.set_page_config(
    page_title="Meraki VPN Rule Checker",
    layout="wide",
    page_icon="🚀"
)

if "api_data" not in st.session_state:
    st.session_state.api_data = None
if "extended_data" not in st.session_state:
    st.session_state.extended_data = None
if "snapshot" not in st.session_state:
    st.session_state.snapshot = {}
if "object_location_map" not in st.session_state:
    st.session_state.object_location_map = {}
if "source_raw_input" not in st.session_state:
    st.session_state.source_raw_input = ""
if "destination_raw_input" not in st.session_state:
    st.session_state.destination_raw_input = ""

# Sidebar - App Controls
st.sidebar.title("Meraki Network Toolkit")
with st.sidebar.expander("🚀 API Access and JSON Import"):
    api_key = st.text_input("API Key", type="password")
    org_id = st.text_input("Organization ID")
    use_api = st.checkbox("Fetch from API", value=False)

    if use_api and api_key and org_id:
        try:
            with st.spinner("Fetching API data..."):
                api_data = fetch_meraki_data(api_key, org_id)
                st.session_state.api_data = api_data
                st.session_state.snapshot["api_data"] = api_data
        except Exception as e:
            st.error(f"API Error: {e}")
    else:
        uploaded_files = {
            "rules": st.file_uploader("Upload Rules JSON", type="json"),
            "objects": st.file_uploader("Upload Objects JSON", type="json"),
            "groups": st.file_uploader("Upload Groups JSON", type="json")
        }
        api_data = parse_uploaded_json(uploaded_files)
        st.session_state.api_data = api_data
        st.session_state.snapshot["api_data"] = api_data

    snapshot_upload = st.file_uploader("Upload Snapshot JSON", type="json", key="snapshot_uploader")
    if snapshot_upload:
        try:
            snapshot = json.load(snapshot_upload)
            st.session_state.api_data = snapshot.get("api_data", {})
            st.session_state.extended_data = snapshot.get("extended_data", {})
            st.session_state.object_location_map = snapshot.get("object_location_map", {})
            st.success("Snapshot loaded.")
        except Exception as e:
            st.error(f"Error loading snapshot: {e}")
# Load saved snapshot
def load_snapshot(snapshot_file):
    snapshot = json.load(snapshot_file)
    st.session_state["vpn_rules"] = snapshot.get("vpn_rules", [])
    st.session_state["objects"] = snapshot.get("objects", [])
    st.session_state["object_groups"] = snapshot.get("object_groups", [])
    st.session_state["extended_api_data"] = snapshot.get("extended_api_data", {})
    st.session_state["object_location_map"] = snapshot.get("object_location_map", {})
    st.session_state["data_source"] = "snapshot"
    st.success("Snapshot loaded successfully.")


# Build location map for snapshot if missing
def update_snapshot_location_map():
    if (
        "extended_api_data" in st.session_state
        and st.session_state["extended_api_data"]
        and (
            "object_location_map" not in st.session_state
            or not st.session_state["object_location_map"]
        )
    ):
        from utils.match_logic import build_object_location_map

        try:
            location_map = build_object_location_map(
                st.session_state["objects"],
                st.session_state["object_groups"],
                st.session_state["extended_api_data"],
            )
            st.session_state["object_location_map"] = location_map
            st.success("Location map built from snapshot data.")
        except Exception as e:
            st.warning(f"⚠️ Failed to rebuild object location map: {e}")
# Page config and session init
st.set_page_config(layout="wide", page_title="Meraki VPN Rule Checker")
if "manual_search_mode" not in st.session_state:
    st.session_state["manual_search_mode"] = False
if "match_results" not in st.session_state:
    st.session_state["match_results"] = {}
if "source_raw_input" not in st.session_state:
    st.session_state["source_raw_input"] = ""
if "destination_raw_input" not in st.session_state:
    st.session_state["destination_raw_input"] = ""

# Sidebar layout
st.sidebar.title("🔧 Toolbox")
with st.sidebar.expander("🔐 API Access", expanded=True):
    api_key = st.text_input("API Key", type="password")
    org_id = st.text_input("Organization ID")
    auto_fetch = st.checkbox("Fetch on load", value=True)
    if st.button("Get API Data"):
        if api_key and org_id:
            try:
                st.session_state["vpn_rules"], st.session_state["objects"], st.session_state["object_groups"] = fetch_meraki_data(
                    api_key, org_id
                )
                st.session_state["data_source"] = "api"
                st.success("Data loaded from API.")
            except Exception as e:
                st.error(f"Failed to fetch API data: {e}")
        else:
            st.warning("Please provide both API Key and Organization ID.")
with st.sidebar.expander("📦 Data Import", expanded=True):
    rules_file = st.file_uploader("Upload Rules JSON", type=["json"], key="rules_file")
    objects_file = st.file_uploader("Upload Objects JSON", type=["json"], key="objects_file")
    groups_file = st.file_uploader("Upload Object Groups JSON", type=["json"], key="groups_file")
    snapshot_file = st.file_uploader("📥 Load Snapshot", type=["json"], key="snapshot_file")

    if snapshot_file:
        try:
            snapshot_data = json.load(snapshot_file)
            st.session_state["vpn_rules"] = snapshot_data.get("vpn_rules", [])
            st.session_state["objects"] = snapshot_data.get("objects", [])
            st.session_state["object_groups"] = snapshot_data.get("object_groups", [])
            st.session_state["extended_api_data"] = snapshot_data.get("extended_api_data", {})
            st.session_state["object_location_map"] = snapshot_data.get("object_location_map", {})
            st.session_state["data_source"] = "snapshot"
            st.success("Snapshot loaded successfully.")
        except Exception as e:
            st.error(f"Failed to load snapshot: {e}")
if rules_file and objects_file and groups_file:
    try:
        st.session_state["vpn_rules"] = json.load(rules_file)
        st.session_state["objects"] = json.load(objects_file)
        st.session_state["object_groups"] = json.load(groups_file)
        st.session_state["data_source"] = "manual"
        st.session_state["extended_api_data"] = {}
        st.session_state["object_location_map"] = build_object_location_map(
            st.session_state["objects"],
            st.session_state["object_groups"],
            st.session_state["extended_api_data"],
        )
        st.success("Files loaded successfully.")
    except Exception as e:
        st.error(f"Error loading files: {e}")

# Refresh Data Button
if st.sidebar.button("🔄 Refresh API Data"):
    if st.session_state.get("headers", {}) and st.session_state.get("org_id", ""):
        try:
            data = fetch_meraki_data(
                st.session_state["headers"], st.session_state["org_id"]
            )
            st.session_state["vpn_rules"] = data["vpn_rules"]
            st.session_state["objects"] = data["objects"]
            st.session_state["object_groups"] = data["object_groups"]
            st.session_state["data_source"] = "api"
            st.success("Refreshed successfully.")
        except Exception as e:
            st.error(f"Error refreshing data: {e}")
# =================== 📦 LOAD SNAPSHOT ===================

st.sidebar.subheader("💾 Snapshot")
snapshot_file = st.sidebar.file_uploader("Load Snapshot JSON", type=["json"])
if snapshot_file:
    try:
        snapshot_data = json.load(snapshot_file)
        st.session_state["vpn_rules"] = snapshot_data.get("vpn_rules", [])
        st.session_state["objects"] = snapshot_data.get("objects", [])
        st.session_state["object_groups"] = snapshot_data.get("object_groups", [])
        st.session_state["extended_api_data"] = snapshot_data.get(
            "extended_api_data", {}
        )
        st.session_state["object_location_map"] = snapshot_data.get(
            "object_location_map", {}
        )
        st.session_state["data_source"] = snapshot_data.get("data_source", "snapshot")
        st.success("Snapshot loaded successfully.")
    except Exception as e:
        st.error(f"Failed to load snapshot: {e}")
# =================== 🧠 AI TOOLSET ===================

with tabs[4]:
    st.title("🧠 AI-Powered Assistant")
    st.markdown("Ask anything about your Meraki configuration.")

    ai_input = st.text_area("💬 Ask a question")
    if st.button("🔍 Analyze with AI"):
        with st.spinner("Thinking..."):
            try:
                # You can integrate OpenAI here if needed
                st.info("🔧 AI feature placeholder — integrate LLM here.")
            except Exception as e:
                st.error(f"AI analysis failed: {e}")

# =================== 🧪 DEBUG TOOLSET ===================

with tabs[5]:
    st.title("🧪 Debug Panel")

    st.write("### Session State")
    st.json(st.session_state)

    st.write("### Raw VPN Rules")
    st.json(st.session_state.get("vpn_rules", []))

    st.write("### Raw Objects")
    st.json(st.session_state.get("objects", []))

    st.write("### Raw Object Groups")
    st.json(st.session_state.get("object_groups", []))

    st.write("### Extended API Data")
    st.json(st.session_state.get("extended_api_data", {}))

    st.write("### Object Location Map")
    st.json(st.session_state.get("object_location_map", {}))
# =================== 📌 PINNING STYLES ===================

pin_style = """
    <style>
    .element-container:has(#location_filter) {
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    </style>
"""
st.markdown(pin_style, unsafe_allow_html=True)

# =================== ✅ DONE ===================

if __name__ == "__main__":
    pass
