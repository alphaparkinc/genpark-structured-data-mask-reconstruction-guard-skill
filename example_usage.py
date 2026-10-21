"""Example usage for GenPark Structured Data Mask Reconstruction Guard."""
from client import StructuredDataMaskGuard

def main():
    guard = StructuredDataMaskGuard()
    users = [
        {"id": "usr_1", "name": "Emily Chen", "email": "emily.chen@techcorp.io", "phone": "+1-555-8921"},
        {"id": "usr_2", "name": "Marcus Vance", "email": "m.vance@finance.org", "phone": "+1-555-4310"}
    ]

    print("Scanning PII...")
    scan = guard.scan_pii_entities(users)
    print(f"Detected PII entities: {scan['pii_findings_count']}")

    print("
Masking records...")
    res = guard.mask_records(users, fields_to_mask=["name", "email", "phone"])
    print("Masked Sample:", res["masked_records"][0])

    print("
Restoring records from vault...")
    restored = guard.unmask_records(res["masked_records"], res["vault"])
    print("Restored Match:", restored[0] == users[0])

if __name__ == "__main__":
    main()
