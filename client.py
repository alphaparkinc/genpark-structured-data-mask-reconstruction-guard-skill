"""Structured Data Mask Reconstruction Guard.
100% Python Standard Library.
"""
import hmac
import hashlib
import re
from typing import Dict, Any, List

class StructuredDataMaskGuard:
    """Deterministic reversible tabular/JSON record anonymizer and de-identification guard."""
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
    PHONE_REGEX = re.compile(r'^\+?[0-9\s\-\(\)]{7,20}$')
    SSN_REGEX = re.compile(r'^\d{3}-\d{2}-\d{4}$')
    CC_REGEX = re.compile(r'^\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}$')

    def __init__(self, master_salt: str = "genpark_default_secret_salt_2026"):
        self.master_salt = master_salt

    def _hash_token(self, val: str, prefix: str = "ANON") -> str:
        h = hmac.new(self.master_salt.encode("utf-8"), val.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
        return f"{prefix}_{h}"

    def scan_pii_entities(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings = []
        for i, rec in enumerate(records):
            for k, v in rec.items():
                if not isinstance(v, str):
                    continue
                v_str = v.strip()
                detected = None
                if self.EMAIL_REGEX.match(v_str):
                    detected = "EMAIL"
                elif self.SSN_REGEX.match(v_str):
                    detected = "SSN"
                elif self.CC_REGEX.match(v_str):
                    detected = "CREDIT_CARD"
                elif "phone" in k.lower() and self.PHONE_REGEX.match(v_str):
                    detected = "PHONE"

                if detected:
                    findings.append({
                        "record_index": i,
                        "field": k,
                        "entity_type": detected,
                        "sample_value_masked": v_str[:2] + "****" + v_str[-2:] if len(v_str) > 4 else "****"
                    })
        return {
            "total_records_scanned": len(records),
            "pii_findings_count": len(findings),
            "findings": findings
        }

    def mask_records(self, records: List[Dict[str, Any]], fields_to_mask: List[str], preserve_format: bool = True) -> Dict[str, Any]:
        vault: Dict[str, str] = {}
        masked_records = []

        for rec in records:
            masked_rec = dict(rec)
            for field in fields_to_mask:
                if field in rec and rec[field] is not None:
                    raw_val = str(rec[field])
                    prefix = field.upper()[:4]
                    if preserve_format and "@" in raw_val:
                        user, domain = raw_val.split("@", 1)
                        h = self._hash_token(user, prefix="USR")
                        token = f"{h}@{domain}"
                    else:
                        token = self._hash_token(raw_val, prefix=prefix)

                    vault[token] = raw_val
                    masked_rec[field] = token
            masked_records.append(masked_rec)

        return {
            "masked_records": masked_records,
            "vault": vault,
            "masked_fields": fields_to_mask,
            "record_count": len(records)
        }

    def unmask_records(self, masked_records: List[Dict[str, Any]], vault: Dict[str, str]) -> List[Dict[str, Any]]:
        restored = []
        for rec in masked_records:
            restored_rec = dict(rec)
            for k, v in rec.items():
                if isinstance(v, str) and v in vault:
                    restored_rec[k] = vault[v]
            restored.append(restored_rec)
        return restored
