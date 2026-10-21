"""MCP Stdio Server for Structured Data Mask Reconstruction Guard.
100% Python Standard Library.
"""
import sys
import json
from client import StructuredDataMaskGuard

guard = StructuredDataMaskGuard()

def handle_rpc(line):
    try:
        req = json.loads(line)
    except Exception:
        return
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if method == "initialize":
        res = {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "genpark-structured-data-mask-reconstruction-guard-skill", "version": "1.0.1"},
            "capabilities": {"tools": {}}
        }
        send_response(req_id, res)
    elif method == "tools/list":
        tools = [
            {
                "name": "scan_pii_entities",
                "description": "Scan records for sensitive PII entities (email, phone, SSN, credit cards)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "records": {"type": "array", "items": {"type": "object"}}
                    },
                    "required": ["records"]
                }
            },
            {
                "name": "mask_records",
                "description": "Deterministically mask sensitive fields with HMAC pseudonyms and return translation vault",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "records": {"type": "array", "items": {"type": "object"}},
                        "fields_to_mask": {"type": "array", "items": {"type": "string"}},
                        "preserve_format": {"type": "boolean", "default": True}
                    },
                    "required": ["records", "fields_to_mask"]
                }
            },
            {
                "name": "unmask_records",
                "description": "Reconstruct original records from masked records and session vault",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "masked_records": {"type": "array", "items": {"type": "object"}},
                        "vault": {"type": "object"}
                    },
                    "required": ["masked_records", "vault"]
                }
            }
        ]
        send_response(req_id, {"tools": tools})
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        if name == "scan_pii_entities":
            out = guard.scan_pii_entities(args.get("records", []))
        elif name == "mask_records":
            out = guard.mask_records(args.get("records", []), args.get("fields_to_mask", []), args.get("preserve_format", True))
        elif name == "unmask_records":
            out = guard.unmask_records(args.get("masked_records", []), args.get("vault", {}))
        else:
            send_error(req_id, -32601, f"Unknown tool: {name}")
            return
        send_response(req_id, {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]})

def send_response(req_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\n")
    sys.stdout.flush()

def send_error(req_id, code, message):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}) + "\n")
    sys.stdout.flush()

def main():
    for line in sys.stdin:
        if line.strip():
            handle_rpc(line.strip())

if __name__ == "__main__":
    main()
