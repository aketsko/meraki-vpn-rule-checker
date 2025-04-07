import requests

def fetch_meraki_data(api_key: str, org_id: str):
    headers = {
        "X-Cisco-Meraki-API-Key": api_key,
        "Content-Type": "application/json",
    }

    base_url = "https://api.meraki.com/api/v1/organizations"

    try:
        # 1. VPN Firewall Rules
        rules_response = requests.get(
            f"{base_url}/{org_id}/appliance/vpn/vpnFirewallRules",
            headers=headers
        )
        rules_response.raise_for_status()

        # 2. Network Objects
        objects_response = requests.get(
            f"{base_url}/{org_id}/policyObjects",
            headers=headers
        )
        objects_response.raise_for_status()

        # 3. Object Groups
        groups_response = requests.get(
            f"{base_url}/{org_id}/policyObjects/groups",
            headers=headers
        )
        groups_response.raise_for_status()

        return {
            "rules": rules_response.json(),      # dict with "rules" key
            "objects": objects_response.json(),  # list
            "groups": groups_response.json(),    # list
        }

    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to fetch Meraki data: {e}")


def fetch_meraki_data_extended(api_key: str, org_id: str, base_url="https://api.meraki.com/api/v1"):
    headers = {
        "X-Cisco-Meraki-API-Key": api_key,
        "Content-Type": "application/json",
    }

    try:
        # Step 1: Get all networks in the org
        networks_url = f"{base_url}/organizations/{org_id}/networks"
        networks_resp = requests.get(networks_url, headers=headers)

        if not networks_resp.ok:
            raise Exception(f"Failed to fetch networks: {networks_resp.text}")
        
        networks = networks_resp.json()
        network_map = {net["name"]: net["id"] for net in networks}

        extended_data = {}

        for net in networks:
            network_id = net["id"]
            network_name = net["name"]

            # Step 2.1: Get site-to-site VPN settings (including local subnets)
            vpn_url = f"{base_url}/networks/{network_id}/appliance/vpn/siteToSiteVpn"
            vpn_resp = requests.get(vpn_url, headers=headers)
            vpn_data = vpn_resp.json() if vpn_resp.ok else {}

            # Step 2.2: Get VPN firewall rules (organization-wide in practice)
            rules_url = f"{base_url}/organizations/{org_id}/appliance/vpn/vpnFirewallRules"
            rules_resp = requests.get(rules_url, headers=headers)
            rules_data = rules_resp.json() if rules_resp.ok else {}

            extended_data[network_id] = {
                "network_name": network_name,
                "vpn_settings": vpn_data,
                "vpn_rules": rules_data.get("rules", [])
            }

        return {
            "networks": networks,
            "network_map": network_map,
            "network_details": extended_data
        }

    except Exception as e:
        return {"error": str(e), "networks": [], "network_map": {}, "network_details": {}}
