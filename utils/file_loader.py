import json

def load_json_file(uploaded_file):
    if uploaded_file is None:
        return {}
    try:
        content = uploaded_file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        return json.loads(content)
    except Exception as e:
        raise ValueError(f"Could not decode uploaded file: {e}")
