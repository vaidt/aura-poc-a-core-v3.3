import hashlib

import rfc8785


class MerkleAttestor:
    """Art. 12 & 13: Cryptographic log immutability."""

    @staticmethod
    def generate_leaf(data: dict) -> str:
        """Return the RFC 6962 leaf digest of the RFC 8785 JCS representation.

        The JCS canonicalization defines the exact UTF-8 bytes being hashed.
        RFC 6962 domain-separates leaf preimages with one raw 0x00 octet:
        SHA-256(0x00 || canonical_json_bytes).

        The returned value remains lowercase hexadecimal for API compatibility.
        """
        canonical_bytes = rfc8785.dumps(data)
        leaf_preimage = b"\x00" + canonical_bytes
        return hashlib.sha256(leaf_preimage).hexdigest()

    def generate_etc(self, ari_result: dict):
        # Event Trust Certificate (ETC)
        leaf = self.generate_leaf(ari_result)
        return {"certificate": f"AURA-ETC-{leaf[:16]}", "proof": [leaf]}
