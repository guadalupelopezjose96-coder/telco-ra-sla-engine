#!/usr/bin/env python3
"""
Motor Automatizado de Conciliación Mayorista de Roaming (GSMA TAP3.12 / BCE),
Auditoría Criptográfica PCI-DSS v4.0 y Gobernanza de Propiedad Intelectual
(OpenChain ISO/IEC 5230 + Regalías de Patentes Esenciales FRAND SEP).
Controles Auditados: FIN-02 y FIN-03.
"""

import json
import re
import hashlib
import uuid
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path


def q2(val: Decimal) -> Decimal:
    """Redondeo financiero a 2 decimales (ROUND_HALF_UP)."""
    return val.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def q6(val: Decimal) -> Decimal:
    """Redondeo de precisión a 6 decimales para tasas SDR / IOT mayoristas."""
    return val.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)


# Clasificación de Licencias SPDX según política OpenChain ISO/IEC 5230 para sistemas Carrier-Grade
PERMISSIVE_SPDX_LICENSES = {
    "BSD-3-Clause",
    "BSD-2-Clause",
    "MIT",
    "Apache-2.0",
    "ISC",
    "MPL-2.0"
}

RESTRICTED_COPYLEFT_LICENSES = {
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "LGPL-3.0-only"
}


class WholesaleAndIpComplianceEngine:
    def __init__(self, data: dict):
        self.data = data
        self.hpmn = data["home_operator_hpmn"]
        self.roaming = data["roaming_wholesale_settlement_fin02"]
        self.pci_data = data["pci_dss_v4_gateway_audit_fin02"]
        self.ip_data = data["sbom_and_frand_sep_audit_fin03"]
        self.sdr_to_eur = Decimal(str(self.hpmn["imf_sdr_to_eur_rate"]))
        self.dispute_threshold_pct = Decimal(str(self.hpmn["dispute_threshold_pct"]))

    def reconcile_gsma_tap3_and_bce(self) -> dict:
        """
        Control FIN-02:
        1. Valida cada lote GSMA TAP3.12 contra las mediciones propias del SBC/SEPP.
        2. Si la discrepancia por archivo supera el 1.00% (Cláusula 6.2), genera un
           registro de rechazo RAP (Returned Accounts Procedure - GSMA TD.32) por el
           exceso y liquida únicamente la porción no controvertida.
        3. Calcula los acuerdos bilaterales BCE (Billing and Charging Evolution) con
           compensación neta (netting) entre tráfico Outbound e Inbound.
        """
        tap3_file_audits = []
        rap_dispute_files = []
        total_undisputed_payable_eur = Decimal("0.00")
        total_disputed_withheld_eur = Decimal("0.00")

        for tap_file in self.roaming["tap3_records_received"]:
            file_id = tap_file["tap_file_id"]
            vpmn = tap_file["vpmn_tadig"]
            claimed_sdr_total = Decimal("0")
            verified_sdr_total = Decimal("0")
            cdr_discrepancies = []

            for cdr in tap_file["call_event_details"]:
                claimed_sdr = Decimal(str(cdr["vpmn_claimed_sdr"]))
                claimed_sdr_total += claimed_sdr

                if cdr["service_type"] == "VoLTE_MO":
                    measured_mins = Decimal(str(cdr["hpmn_sepp_sbc_measured_seconds"])) / Decimal("60")
                    rate = Decimal(str(cdr["iot_rate_sdr_per_min"]))
                    recalculated_sdr = q6(measured_mins * rate)
                else:
                    measured_mb = Decimal(str(cdr["hpmn_sepp_sbc_measured_megabytes"]))
                    rate = Decimal(str(cdr["iot_rate_sdr_per_mb"]))
                    recalculated_sdr = q6(measured_mb * rate)

                verified_sdr_total += recalculated_sdr
                diff_sdr = claimed_sdr - recalculated_sdr

                if diff_sdr > Decimal("0.000100"):
                    cdr_discrepancies.append({
                        "cdr_id": cdr["cdr_id"],
                        "service_type": cdr["service_type"],
                        "claimed_sdr": str(claimed_sdr),
                        "verified_sdr": str(recalculated_sdr),
                        "overcharge_sdr": str(q6(diff_sdr))
                    })

            overcharge_total_sdr = claimed_sdr_total - verified_sdr_total
            discrepancy_pct = (
                (overcharge_total_sdr / claimed_sdr_total) * Decimal("100")
                if claimed_sdr_total > 0 else Decimal("0")
            )

            claimed_eur = q2(claimed_sdr_total * self.sdr_to_eur)
            verified_eur = q2(verified_sdr_total * self.sdr_to_eur)

            # Regla GSMA BA.27 / Cláusula 6.2: Disputa formal (RAP) si supera el 1.00%
            if discrepancy_pct > self.dispute_threshold_pct:
                settlement_status = "PARTIAL_DISPUTE_RAP_ISSUED"
                payable_now_eur = verified_eur
                disputed_eur = q2(claimed_eur - verified_eur)
                rap_id = f"RAP-{self.hpmn['tadig_code']}-{vpmn}-{uuid.uuid4().hex[:6].upper()}"
                rap_dispute_files.append({
                    "rap_file_id": rap_id,
                    "referenced_tap_file_id": file_id,
                    "vpmn_tadig": vpmn,
                    "gsma_return_code": "RC-204 (Volume/Charge Discrepancy > 1.00% SLA Threshold)",
                    "disputed_sdr": str(q6(overcharge_total_sdr)),
                    "disputed_eur": str(disputed_eur),
                    "affected_cdrs": cdr_discrepancies
                })
            else:
                settlement_status = "ACCEPTED_WITHIN_TOLERANCE"
                payable_now_eur = claimed_eur
                disputed_eur = Decimal("0.00")

            total_undisputed_payable_eur += payable_now_eur
            total_disputed_withheld_eur += disputed_eur

            tap3_file_audits.append({
                "tap_file_id": file_id,
                "vpmn_tadig": vpmn,
                "vpmn_name": tap_file["vpmn_name"],
                "claimed_sdr": str(q6(claimed_sdr_total)),
                "verified_sdr": str(q6(verified_sdr_total)),
                "discrepancy_pct": str(q2(discrepancy_pct)),
                "settlement_status": settlement_status,
                "undisputed_payable_eur": str(payable_now_eur),
                "disputed_withheld_eur": str(disputed_eur),
                "cdi_tax_residency_verified": tap_file["w8ben_or_tax_residency_valid"]
            })

        # Liquidación de Acuerdos Bilaterales GSMA BCE (Billing and Charging Evolution)
        bce_settlements = []
        for bce in self.roaming["bce_bilateral_deals"]:
            out = bce["outbound_traffic"]
            voice_sdr = Decimal(str(out["voice_minutes"])) * Decimal(str(out["rate_sdr_per_min"]))
            data_sdr = Decimal(str(out["data_gigabytes"])) * Decimal(str(out["rate_sdr_per_gb"]))
            iot_sdr = Decimal(str(out["nb_iot_active_sims"])) * Decimal(str(out["rate_sdr_per_sim"]))
            usage_outbound_sdr = voice_sdr + data_sdr + iot_sdr

            floor_sdr = Decimal(str(bce["committed_monthly_floor_sdr"]))
            effective_outbound_payable_sdr = max(floor_sdr, usage_outbound_sdr)
            inbound_receivable_sdr = Decimal(str(bce["inbound_traffic_offset"]["total_inbound_receivable_sdr"]))

            # Compensación Neta Financiera (Netting Clearing House)
            net_position_sdr = effective_outbound_payable_sdr - inbound_receivable_sdr
            net_position_eur = q2(net_position_sdr * self.sdr_to_eur)

            total_undisputed_payable_eur += net_position_eur

            bce_settlements.append({
                "bce_settlement_id": bce["bce_settlement_id"],
                "partner_tadig": bce["partner_tadig"],
                "calculated_outbound_usage_sdr": str(q2(usage_outbound_sdr)),
                "committed_floor_sdr": str(q2(floor_sdr)),
                "effective_outbound_sdr": str(q2(effective_outbound_payable_sdr)),
                "inbound_receivable_offset_sdr": str(q2(inbound_receivable_sdr)),
                "net_clearing_payable_sdr": str(q2(net_position_sdr)),
                "net_clearing_payable_eur": str(net_position_eur)
            })

        return {
            "imf_sdr_to_eur_exchange_rate": str(self.sdr_to_eur),
            "tap3_files_reconciled": tap3_file_audits,
            "gsma_rap_disputes_generated": rap_dispute_files,
            "bce_bilateral_netting": bce_settlements,
            "clearing_house_summary": {
                "total_undisputed_net_payable_eur": str(q2(total_undisputed_payable_eur)),
                "total_disputed_held_in_escrow_eur": str(q2(total_disputed_withheld_eur))
            }
        }

    @staticmethod
    def _contains_unmasked_luhn_pan(text: str) -> bool:
        """
        Escanea cadenas en busca de secuencias de 13 a 19 dígitos continuos que
        superen el algoritmo de Luhn (ISO/IEC 7812), indicando un PAN en texto claro.
        """
        candidates = re.findall(r"\b\d{13,19}\b", text)
        for cand in candidates:
            digits = [int(d) for d in cand]
            checksum = 0
            parity = len(digits) % 2
            for idx, digit in enumerate(digits):
                if idx % 2 == parity:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
            if checksum % 10 == 0:
                return True
        return False

    def audit_pci_dss_v4_compliance(self) -> dict:
        """
        Control FIN-02 (PCI-DSS v4.0 Req 3.2 y 3.4):
        Verifica que ningún log o payload de recarga contenga CVV/CVC, Track Data
        o números PAN sin enmascarar.
        """
        violations = []
        sensitive_auth_patterns = re.compile(r"(CVV2?|CVC2?|PIN_BLOCK|TRACK[12])=", re.IGNORECASE)

        for entry in self.pci_data["sampled_payment_logs"]:
            raw = entry["raw_payload_inspection"]
            masked = entry["masked_pan"]

            if sensitive_auth_patterns.search(raw):
                violations.append(f"Tx {entry['tx_id']}: Sensitive Authentication Data (CVV/Track) detected.")
            if self._contains_unmasked_luhn_pan(raw):
                violations.append(f"Tx {entry['tx_id']}: Unmasked Luhn-valid PAN detected in payload.")
            if not re.match(r"^\d{6}\*{4,9}\d{4}$", masked):
                violations.append(f"Tx {entry['tx_id']}: Invalid BIN/Last4 masking format ({masked}).")

        if violations:
            raise RuntimeError(f"Fallo Crítico PCI-DSS v4.0: {violations}")

        return {
            "standard": "PCI-DSS v4.0 (Requirements 3.2, 3.3, 3.4)",
            "aoc_certificate_id": self.pci_data["aoc_certificate_id"],
            "sampled_transactions_count": len(self.pci_data["sampled_payment_logs"]),
            "unmasked_pan_or_cvv_leaks": 0,
            "pci_audit_verdict": "COMPLIANT_ZERO_CHD_STORAGE"
        }

    def audit_openchain_sbom_and_frand_royalties(self) -> dict:
        """
        Control FIN-03:
        1. Audita el documento SPDX 2.3 bajo la norma OpenChain ISO/IEC 5230:
           - Prohíbe licencias Copyleft vinculadas estática/dinámicamente a binarios
             propietarios del plano de datos o control.
           - Permite procesos aislados del sistema operativo (ej. FRR / strongSwan)
             que se comunican exclusivamente por IPC/NETCONF estándar sin modificar
             o enlazar código propietario.
        2. Calcula las regalías devengadas por Patentes Esenciales Estándar (FRAND SEP)
           y verifica que el uso pico no supere el techo de licencias contratadas.
        """
        sbom = self.ip_data["spdx_sbom_document"]
        package_audits = []
        copyleft_contamination_alerts = []

        for pkg in sbom["packages"]:
            lic = pkg["licenseDeclared"]
            ctx = pkg["usageContext"]

            if lic in PERMISSIVE_SPDX_LICENSES:
                compliance_state = "APPROVED_PERMISSIVE"
            elif lic in RESTRICTED_COPYLEFT_LICENSES:
                if "LINKED_INTO_PROPRIETARY" in ctx or "NETWORK_EXPOSED_SAAS_MODIFIED" in ctx:
                    compliance_state = "VIOLATION_COPYLEFT_CONTAMINATION"
                    copyleft_contamination_alerts.append(
                        f"Paquete {pkg['name']} ({lic}) enlazado en binario propietario ({ctx})."
                    )
                else:
                    compliance_state = "APPROVED_ISOLATED_OS_PROCESS_WITH_SOURCE_ARCHIVE"
            else:
                compliance_state = "VIOLATION_UNAPPROVED_OR_NOASSERTION_LICENSE"
                copyleft_contamination_alerts.append(
                    f"Paquete {pkg['name']} con licencia no autorizada: {lic}"
                )

            package_audits.append({
                "spdx_id": pkg["SPDXID"],
                "package_name": pkg["name"],
                "version": pkg["versionInfo"],
                "license_declared": lic,
                "usage_context": ctx,
                "openchain_verdict": compliance_state
            })

        if copyleft_contamination_alerts:
            raise RuntimeError(f"Bloqueo Legal FIN-03 (OpenChain ISO/IEC 5230): {copyleft_contamination_alerts}")

        # Auditoría de Patentes Esenciales Estándar (FRAND SEP)
        sep_audits = []
        total_frand_royalties_eur = Decimal("0.00")

        for pool in self.ip_data["frand_sep_patent_portfolios"]:
            cap = int(pool["licensed_channel_cap"])
            peak = int(pool["active_concurrent_channels_peak"])
            rate = Decimal(str(pool["royalty_rate_eur_per_active_channel"]))

            if peak > cap:
                raise RuntimeError(
                    f"Incumplimiento de Licencia FRAND SEP ({pool['patent_pool_id']}): "
                    f"Pico {peak} supera el techo contratado de {cap}."
                )

            utilization_pct = q2((Decimal(str(peak)) / Decimal(str(cap))) * Decimal("100"))
            accrued_royalty_eur = q2(Decimal(str(peak)) * rate)
            total_frand_royalties_eur += accrued_royalty_eur

            sep_audits.append({
                "patent_pool_id": pool["patent_pool_id"],
                "standard_reference": pool["standard_reference"],
                "licensor_entity": pool["licensor_entity"],
                "licensed_cap": cap,
                "peak_active_units": peak,
                "license_utilization_pct": str(utilization_pct),
                "accrued_monthly_royalty_eur": str(accrued_royalty_eur),
                "frand_status": pool["contract_status"]
            })

        return {
            "openchain_standard": "ISO/IEC 5230:2020 (OpenChain) & ISO/IEC 5962:2021 (SPDX 2.3)",
            "sbom_document_name": sbom["name"],
            "total_packages_audited": len(package_audits),
            "copyleft_contamination_incidents": 0,
            "sbom_package_verdicts": package_audits,
            "frand_sep_royalty_settlement": {
                "patent_pools_audited": sep_audits,
                "total_monthly_frand_royalties_accrued_eur": str(q2(total_frand_royalties_eur)),
                "ledger_account": "626100 - Royalties for Standard Essential Patents (FRAND SEP)"
            }
        }


def main():
    base_dir = Path(__file__).resolve().parent.parent
    input_path = base_dir / "data" / "roaming_pci_sbom_input.json"
    out_dir = base_dir / "output" / "fin02_fin03"
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(input_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    engine = WholesaleAndIpComplianceEngine(payload)

    # 1. Conciliación Mayorista GSMA TAP3 / BCE
    roaming_settlement = engine.reconcile_gsma_tap3_and_bce()

    # 2. Auditoría Criptográfica PCI-DSS v4.0
    pci_audit = engine.audit_pci_dss_v4_compliance()

    # 3. Auditoría OpenChain ISO/IEC 5230 y Regalías FRAND SEP
    ip_frand_audit = engine.audit_openchain_sbom_and_frand_royalties()

    master_report = {
        "certificate_id": f"FIN02-FIN03-CERT-{uuid.uuid4().hex[:8].upper()}",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "controls_verified": ["FIN-02", "FIN-03"],
        "fin02_wholesale_roaming_and_pci": {
            "gsma_tap3_bce_settlement": roaming_settlement,
            "pci_dss_v4_audit": pci_audit
        },
        "fin03_openchain_and_frand_sep": ip_frand_audit
    }

    payload_bytes = json.dumps(master_report, sort_keys=True).encode("utf-8")
    master_report["worm_integrity_sha384"] = hashlib.sha384(payload_bytes).hexdigest()

    out_file = out_dir / "fin02_fin03_wholesale_ip_certificate.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(master_report, f, indent=2, ensure_ascii=False)

    print("========================================================================================")
    print(" MOTOR DE CONCILIACIÓN ROAMING (TAP3/BCE), PCI-DSS v4.0 Y AUDITORÍA SBOM/FRAND EJECUTADO")
    print("========================================================================================")
    print(f"• Archivos GSMA TAP3 Auditados (FIN-02) : {len(roaming_settlement['tap3_files_reconciled'])} lotes")
    print(f"• Disputas GSMA RAP Emitidas (>1% SLA)  : {len(roaming_settlement['gsma_rap_disputes_generated'])} "
          f"(Retenido en disputa: {roaming_settlement['clearing_house_summary']['total_disputed_held_in_escrow_eur']} EUR)")
    print(f"• Total Neto a Pagar Clearing House     : {roaming_settlement['clearing_house_summary']['total_undisputed_net_payable_eur']} EUR (TAP3 + Netting BCE)")
    print(f"• Auditoría PCI-DSS v4.0 (FIN-02)       : {pci_audit['pci_audit_verdict']} (0 fugas PAN/CVV en {pci_audit['sampled_transactions_count']} muestras)")
    print(f"• Auditoría SBOM OpenChain ISO 5230     : {ip_frand_audit['copyleft_contamination_incidents']} incidentes Copyleft en {ip_frand_audit['total_packages_audited']} paquetes SPDX 2.3")
    print(f"• Regalías Devengadas FRAND SEP (FIN-03): {ip_frand_audit['frand_sep_royalty_settlement']['total_monthly_frand_royalties_accrued_eur']} EUR (3GPP EVS/AMR-WB, HEVC, 5G NR)")
    print(f"• Certificado Forense WORM exportado en : {out_file}")
    print("========================================================================================")


if __name__ == "__main__":
    main()
