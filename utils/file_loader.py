# utils/file_loader.py
import json

def load_json_file(uploaded_file):
    try:
        # Handle Streamlit UploadedFile and file-like objects
        if hasattr(uploaded_file, "read"):
            content = uploaded_file.read()
            if isinstance(content, bytes):
                content = content.decode("utf-8")
        elif isinstance(uploaded_file, str):
            content = uploaded_file
        else:
            raise ValueError("Unsupported file type")

        return json.loads(content)
    except Exception as e:
        raise ValueError(f"Could not decode uploaded file: {e}")
