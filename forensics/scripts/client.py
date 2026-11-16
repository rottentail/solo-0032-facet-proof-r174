"""Minimal HTTP client for driving the local Facet Proof service.

Only Python standard-library modules are used. Every response is returned as
(parsed_json_or_None, raw_bytes, mime, status) so callers can keep exact bytes
for hashing and for the evidence chain of custody.
"""
import http.client
import json


class ServiceError(RuntimeError):
    def __init__(self, status, payload):
        super().__init__(f"HTTP {status}: {payload}")
        self.status = status
        self.payload = payload


class Client:
    def __init__(self, host="127.0.0.1", port=8796):
        self.host, self.port = host, port

    def request(self, method, path, body=None, expect=200):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
        try:
            headers = {}
            payload = b""
            if body is not None:
                payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
                headers["Content-Type"] = "application/json"
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            raw = response.read()
            mime = response.getheader("Content-Type", "")
            status = response.status
        finally:
            conn.close()
        if status != expect:
            try:
                detail = json.loads(raw.decode("utf-8"))
            except Exception:
                detail = raw[:200]
            raise ServiceError(status, detail)
        if mime.startswith("application/json"):
            return json.loads(raw.decode("utf-8")), raw, mime, status
        return None, raw, mime, status

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body=None):
        return self.request("POST", path, body if body is not None else {})

    def put(self, path, body):
        return self.request("PUT", path, body)
