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
