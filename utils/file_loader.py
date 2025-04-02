import json

def load_json_file(uploaded_file):
    if uploaded_file:
        return json.load(uploaded_file)
    return None