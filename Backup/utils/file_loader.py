import json
import io

def load_json_file(uploaded_file):
    try:
        if uploaded_file is None:
            raise ValueError("No file provided")

        content = uploaded_file.read()
        if not content:
            raise ValueError("Uploaded file is empty")

        if isinstance(content, bytes):
            content = content.decode("utf-8")

        content = content.strip()
        if not content:
            raise ValueError("Uploaded file contains no data")

        return json.loads(content)

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")
    except Exception as e:
        raise ValueError(f"Error reading uploaded file: {e}")
