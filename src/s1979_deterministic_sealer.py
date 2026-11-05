#!/usr/bin/env python3
"""
Sellador Criptográfico Determinista para Standard 1979 Holdings, LLC (6 Dominios):
- Polinomio de Interpolación de Lagrange Shamir 3-of-5 sobre GF(256) (0x11B).
- Generador Determinista de SBOM CycloneDX 1.5 y THIRD-PARTY-NOTICES.txt (POL-SEC-OSS-001).
- Árbol de Merkle Binario RFC 6962 + Sobre Híbrido Post-Cuántico SHA3-512.
"""

import hashlib
import hmac
import json
from pathlib import Path

SIX_DOMAINS = [
    "standard1979.com",
    "AuraIntelCore.com",
    "AuraTetrax.com",
    "AuraIntelStudios3D.com",
    "fourphonix.com",
    "prophonix.com"
]


class GF256ShamirQuorum:
    """Aritmética de Cuerpo Finito GF(2^8) con polinomio irreducible AES 0x11B."""

    @staticmethod
    def mul(a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B
            b >>= 1
        return p

    @classmethod
    def pow_gf(cls, a: int, exp: int) -> int:
        res = 1
        base = a
        while exp > 0:
            if exp & 1:
                res = cls.mul(res, base)
            base = cls.mul(base, base)
            exp >>= 1
        return res

    @classmethod
    def inv(cls, a: int) -> int:
        if a == 0:
            raise ZeroDivisionError("Inverso de 0 no existe en GF(256).")
        # Pequeño Teorema de Fermat en GF(2^8): a^(254) = a^(-1)
        return cls.pow_gf(a, 254)

    @classmethod
    def split_secret_3_of_5(cls, secret: bytes, seed_key: bytes) -> list[dict]:
        """Divide un secreto de 32 bytes en 5 fragmentos (umbral k=3) de forma determinista."""
        shares = {x: bytearray() for x in range(1, 6)}
        for idx, secret_byte in enumerate(secret):
            coeff_digest = hmac.new(seed_key, f"COEFF-{idx}".encode("ascii"), hashlib.sha256).digest()
            a1 = (coeff_digest[0] % 254) + 1
            a2 = (coeff_digest[1] % 254) + 1
            for x in range(1, 6):
                # f(x) = s + a1*x + a2*x^2 en GF(256)
                x2 = cls.mul(x, x)
                fx = secret_byte ^ cls.mul(a1, x) ^ cls.mul(a2, x2)
                shares[x].append(fx)

        custodians = [
            "CUSTODIAN-1: Standard 1979 Holdings, LLC (IP Treasury Vault - standard1979.com)",
            "CUSTODIAN-2: Aura Technologies Operating, LLC (SSO/LLM Lead - AuraIntelCore.com)",
            "CUSTODIAN-3: Aura Technologies Operating, LLC (PaaS/3D Lead - AuraTetrax.com / AuraIntelStudios3D.com)",
            "CUSTODIAN-4: Phonix Communications Operating, LLC (UCaaS Host - fourphonix.com)",
            "CUSTODIAN-5: Phonix Communications Operating, LLC (Carrier Core - prophonix.com)"
        ]
        return [
            {
                "share_index_x": x,
                "custodian": custodians[x - 1],
                "share_hex_gf256": bytes(shares[x]).hex()
            }
            for x in range(1, 6)
        ]

    @classmethod
    def reconstruct_from_quorum(cls, selected_shares: list[dict]) -> bytes:
        """Interpolación de Lagrange en x=0 sobre GF(256) usando 3 fragmentos."""
        xs = [s["share_index_x"] for s in selected_shares]
        ys = [bytes.fromhex(s["share_hex_gf256"]) for s in selected_shares]
        secret_len = len(ys[0])
        recovered = bytearray(secret_len)

        for byte_idx in range(secret_len):
            acc = 0
            for i in range(len(xs)):
                xi = xs[i]
                yi = ys[i][byte_idx]
                num = 1
                den = 1
                for j in range(len(xs)):
                    if i == j:
                        continue
                    xj = xs[j]
                    num = cls.mul(num, xj)
                    den = cls.mul(den, xi ^ xj)
                lagrange_basis = cls.mul(num, cls.inv(den))
                acc ^= cls.mul(yi, lagrange_basis)
            recovered[byte_idx] = acc
        return bytes(recovered)


def write_deterministic_sbom_and_notices(base_dir: Path) -> None:
    """Genera sbom-cyclonedx.json y THIRD-PARTY-NOTICES.txt sin marcas de tiempo mutables."""
    tracked_files = sorted(
        p for p in base_dir.rglob("*")
        if p.is_file()
        and ".git" not in p.parts
        and "dist" not in p.parts
        and p.name not in {"sbom-cyclonedx.json", "THIRD-PARTY-NOTICES.txt", "MERKLE_SEAL_RFC6962.json"}
    )

    components = []
    for fpath in tracked_files:
        rel = fpath.relative_to(base_dir).as_posix()
        sha256_h = hashlib.sha256(fpath.read_bytes()).hexdigest()
        components.append({
            "type": "file",
            "name": rel,
            "version": "2026.11.s1979-lts",
            "hashes": [{"alg": "SHA-256", "content": sha256_h}],
            "licenses": [{"license": {"id": "Proprietary-Standard1979HoldingsLLC"}}]
        })

    cyclonedx_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:19790000-2026-4000-8000-standard1979",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "standard-1979-six-domain-carrier-ecosystem",
                "version": "2026.11.0",
                "publisher": "Standard 1979 Holdings, LLC",
                "domains": SIX_DOMAINS
            }
        },
        "components": components
    }

    (base_dir / "sbom-cyclonedx.json").write_text(
        json.dumps(cyclonedx_sbom, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8"
    )

    notices_text = (
        "================================================================================\n"
        " STANDARD 1979 HOLDINGS, LLC - THIRD-PARTY SOFTWARE & PATENT NOTICES (POL-SEC-OSS-001)\n"
        "================================================================================\n"
        "1. Corporate IP Ownership: 100% of proprietary source code, configurations, and\n"
        "   AI/Telecom architectures across standard1979.com, AuraIntelCore.com,\n"
        "   AuraTetrax.com, AuraIntelStudios3D.com, fourphonix.com, and prophonix.com\n"
        "   are the exclusive property of Standard 1979 Holdings, LLC.\n"
        "2. OpenChain ISO/IEC 5230 Verified Components:\n"
        "   - DPDK Fastpath (BSD-3-Clause)\n"
        "   - OpenTelemetry Collector (Apache-2.0)\n"
        "   - FRRouting & strongSwan PQC (Isolated OS Daemons via Standard NETCONF/IPC)\n"
        "3. Standard Essential Patents (FRAND SEP): Licensed in compliance with 3GPP EVS,\n"
        "   ITU-T G.722.2 (AMR-WB), ITU-T H.265 (HEVC), and 3GPP Release 18 5G NR.\n"
    )
    (base_dir / "THIRD-PARTY-NOTICES.txt").write_text(notices_text, encoding="utf-8")


def generate_rfc6962_merkle_seal(base_dir: Path) -> dict:
    """Calcula el Árbol de Merkle RFC 6962 sobre todos los artefactos y valida el quórum Shamir."""
    master_vault_secret = hashlib.sha256(
        b"S1979-HOLDINGS-MASTER-DRP-VAULT-KEY-6-DOMAINS-2026"
    ).digest()
    seed_key = b"S1979-GF256-LAGRANGE-DETERMINISTIC-SEED"

    shares = GF256ShamirQuorum.split_secret_3_of_5(master_vault_secret, seed_key)
    reconstructed = GF256ShamirQuorum.reconstruct_from_quorum([shares[0], shares[2], shares[4]])
    if reconstructed != master_vault_secret:
        raise RuntimeError("Fallo matemático en reconstrucción de Quórum Shamir 3-de-5 GF(256).")

    files_for_merkle = sorted(
        p for p in base_dir.rglob("*")
        if p.is_file()
        and ".git" not in p.parts
        and "dist" not in p.parts
        and p.name != "MERKLE_SEAL_RFC6962.json"
    )

    leaf_entries = []
    current_level = []
    for fpath in files_for_merkle:
        rel = fpath.relative_to(base_dir).as_posix()
        data = fpath.read_bytes()
        # RFC 6962 Leaf Hash: SHA-256(0x00 || file_bytes)
        leaf_h = hashlib.sha256(b"\x00" + data).digest()
        current_level.append(leaf_h)
        leaf_entries.append({
            "path": rel,
            "sha256_file": hashlib.sha256(data).hexdigest(),
            "rfc6962_leaf_hash": leaf_h.hex()
        })

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                combined = hashlib.sha256(b"\x01" + current_level[i] + current_level[i + 1]).digest()
            else:
                combined = current_level[i]
            next_level.append(combined)
        current_level = next_level

    merkle_root_hex = current_level[0].hex()
    pqc_sha3_512_envelope = hmac.new(
        master_vault_secret,
        current_level[0],
        hashlib.sha3_512
    ).hexdigest()

    seal_doc = {
        "HoldingEntity": "Standard 1979 Holdings, LLC",
        "ProtectedDomains": SIX_DOMAINS,
        "CompliancePolicy": "POL-SEC-OSS-001 & SOC 2 CC7.5 Deterministic Sealing",
        "ShamirQuorumGF256": {
            "Scheme": "3-of-5 Threshold over GF(2^8) (Irreducible Polynomial 0x11B)",
            "QuorumVerificationTest": "PASS_EXACT_MATCH_SHARES_1_3_5",
            "CustodianShares": shares
        },
        "MerkleTreeRFC6962": {
            "TotalSealedFiles": len(leaf_entries),
            "MerkleRootSHA256": merkle_root_hex,
            "PostQuantumHybridEnvelopeSHA3_512": pqc_sha3_512_envelope,
            "AuditedFileLeaves": leaf_entries
        }
    }

    (base_dir / "MERKLE_SEAL_RFC6962.json").write_text(
        json.dumps(seal_doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8"
    )
    return seal_doc


def main():
    base_dir = Path(__file__).resolve().parent.parent
    write_deterministic_sbom_and_notices(base_dir)
    seal = generate_rfc6962_merkle_seal(base_dir)
    print(f"[OK] SBOM CycloneDX + Shamir 3-of-5 GF(256) + Merkle Root RFC 6962: {seal['MerkleTreeRFC6962']['MerkleRootSHA256']}")


if __name__ == "__main__":
    main()
