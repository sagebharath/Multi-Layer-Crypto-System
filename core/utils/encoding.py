import base64

def bytes_to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def b64_to_bytes(data_str: str) -> bytes:
      return base64.b64decode(data_str.encode("utf-8"))

def str_to_bytes(text: str) -> bytes:
      return text.encode("utf-8")

def bytes_to_str(data: bytes) -> str:
      return data.decode("utf-8", errors="ignore")

