import json

def load_json_file(uploaded_file):
    if uploaded_file is None:
        return {}
    content = uploaded_file.read()
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    return json.loads(content)
