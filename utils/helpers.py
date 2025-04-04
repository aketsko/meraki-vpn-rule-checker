# ------------------ HELPER FUNCTIONS ------------------

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
            return [object_map[obj_id]["cidr"] for obj_id in group["objectIds"]
                    if obj_id in object_map and "cidr" in object_map[obj_id]]
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
