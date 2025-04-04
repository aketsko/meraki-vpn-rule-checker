import pandas as pd
import json

def load_json_file(uploaded_file):
    if uploaded_file:
        return json.load(uploaded_file)
    return None
    
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
