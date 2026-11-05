#!/usr/bin/env python3
"""
Motor Multi-Jurisdiccional de Cumplimiento Regulatorio (GOV) y Liquidación Fiscal (FIN)
para Sistemas de Comunicaciones Carrier-Grade.
Jurisdicciones Soportadas: Estados Unidos (US), España (ES), México (MX), Colombia (CO).
Controles Auditados: GOV-01 a GOV-06, FIN-01, FIN-04, FIN-05.
"""

import json
import hashlib
import uuid
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
import xml.etree.ElementTree as ET
from xml.dom import minidom


def q2(val: Decimal) -> Decimal:
    """Redondeo fiscal estándar a 2 decimales (ROUND_HALF_UP)."""
    return val.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


class MultiJurisdictionTelcoEngine:
    """
    Calcula impuestos indirectos, impuestos especiales a las telecomunicaciones,
    contribuciones a fondos de servicio universal (USF/FUTIC/FNSU), retenciones
    internacionales y genera los comprobantes electrónicos locales.
    """

    def __init__(self):
        self.timestamp_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.date_only = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.time_only = datetime.now(timezone.utc).strftime("%H:%M:%S-05:00")

    def calculate_us_fcc_usac_settlement(self, credit_base_usd: Decimal, is_interstate: bool = True) -> dict:
        """
        ESTADOS UNIDOS (US):
        - Federal Excise Tax (FET - IRC § 4251): 3.00% sobre servicios locales/voz.
        - State & Local Communications Services Tax (CST - ej. Florida/Texas avg): 7.44%.
        - Federal Universal Service Fund (USF - USAC Form 499-Q): 34.60% sobre porción interestatal.
        - FCC Regulatory Fee + TRS/NANPA: 0.54%.
        """
        fet_rate = Decimal("0.0300")
        cst_rate = Decimal("0.0744")
        usf_rate = Decimal("0.3460") if is_interstate else Decimal("0.0000")
        fcc_reg_rate = Decimal("0.0054")

        fet_adj = q2(credit_base_usd * fet_rate)
        cst_adj = q2(credit_base_usd * cst_rate)
        usf_surcharge_adj = q2(credit_base_usd * usf_rate)
        fcc_reg_adj = q2(credit_base_usd * fcc_reg_rate)

        total_tax_and_usf_adj = q2(fet_adj + cst_adj + usf_surcharge_adj + fcc_reg_adj)
        total_gross_credit = q2(credit_base_usd + total_tax_and_usf_adj)

        return {
            "jurisdiction": "United States (Federal FCC + State CST)",
            "regulatory_framework": {
                "nra": "Federal Communications Commission (FCC) & USAC",
                "lawful_interception": "CALEA (47 U.S.C. § 1001) / ATIS-1000678 (J-STD-025)",
                "call_authentication": "TRACED Act - STIR/SHAKEN & Robocall Mitigation Database (RMD)",
                "incident_reporting_sla": "CIRCIA (72h to CISA) & FCC Data Breach Portal (7 business days)",
                "accounting_standard": "US GAAP ASC 606 (Variable Consideration) & ASC 842"
            },
            "tax_breakdown": {
                "currency": "USD",
                "taxable_credit_base": str(q2(credit_base_usd)),
                "federal_excise_tax_3pct": str(fet_adj),
                "state_communications_services_tax_7_44pct": str(cst_adj),
                "usac_universal_service_fund_34_6pct": str(usf_surcharge_adj),
                "fcc_regulatory_trs_nanpa_fee_0_54pct": str(fcc_reg_adj),
                "total_taxes_and_surcharges_reversed": str(total_tax_and_usf_adj),
                "total_credit_note_gross": str(total_gross_credit)
            },
            "compliance_forms": ["FCC Form 499-Q (Quarterly USF True-Up)", "FCC Form 499-A", "IRS Form 720 (FET)", "IRS Form W-8BEN-E (CDI)"]
        }

    def calculate_spain_aeat_cnmc_settlement(self, credit_base_eur: Decimal, previous_verifactu_hash: str) -> dict:
        """
        ESPAÑA (ES):
        - IVA General (Ley 37/1992): 21.00% sobre la base imponible.
        - Tasa General de Operadores (Ley 11/2022 Anexo I): 0.10% (1 por mil) sobre ingresos brutos.
        - Aportación al Fondo Nacional del Servicio Universal (FNSU - CNMC): 0.15% estimado.
        - Suministro Inmediato de Información (SII) y Huella Encadenada Veri*factu (AEAT).
        """
        iva_rate = Decimal("0.2100")
        tgo_cnmc_rate = Decimal("0.0010")
        fnsu_rate = Decimal("0.0015")

        iva_adj = q2(credit_base_eur * iva_rate)
        total_gross_credit = q2(credit_base_eur + iva_adj)
        tgo_reduction = q2(credit_base_eur * tgo_cnmc_rate)
        fnsu_reduction = q2(credit_base_eur * fnsu_rate)

        serie_num = f"R-SLA-{self.date_only.replace('-', '')}-001"
        nif_emisor = "B99887766"

        # Generación de huella encadenada SHA-256 conforme a especificación técnica Veri*factu / SII AEAT
        verifactu_canonical_str = (
            f"IDEmisorFactura={nif_emisor}&NumSerieFactura={serie_num}&"
            f"FechaExpedicionFactura={self.date_only}&TipoFactura=R1&"
            f"CuotaTotal=-{iva_adj}&ImporteTotal=-{total_gross_credit}&"
            f"Huella={previous_verifactu_hash}&FechaHoraHusoGenRegistro={self.timestamp_iso}"
        )
        verifactu_sha256 = hashlib.sha256(verifactu_canonical_str.encode("utf-8")).hexdigest().upper()

        return {
            "jurisdiction": "España (AEAT / CNMC / Unión Europea)",
            "regulatory_framework": {
                "nra": "Comisión Nacional de los Mercados y la Competencia (CNMC) & SETSI",
                "statute": "Ley 11/2022 General de Telecomunicaciones & Real Decreto-ley 7/2022 (Seguridad 5G)",
                "lawful_interception": "Ley 25/2007 (Retención 12 meses) + Sistema SITEL (ETSI TS 102 232)",
                "incident_reporting_sla": "Directiva NIS2 / CCN-CERT / INCIBE-CERT (Alerta temprana < 24h, Informe < 72h)",
                "accounting_standard": "PGC Real Decreto 1/2021 / NIIF-UE 15 (Contraprestación Variable)"
            },
            "tax_breakdown": {
                "currency": "EUR",
                "taxable_credit_base": str(q2(credit_base_eur)),
                "iva_21pct_adjustment": str(iva_adj),
                "total_credit_note_gross": str(total_gross_credit),
                "regulatory_levies_reversed": {
                    "tasa_general_operadores_1permil": str(tgo_reduction),
                    "fondo_nacional_servicio_universal_fnsu": str(fnsu_reduction)
                }
            },
            "aeat_sii_verifactu_artifact": {
                "invoice_type_code": "R1 (Factura Rectificativa por Art. 80.1 y 80.2 LIVA - SLA)",
                "invoice_series_number": serie_num,
                "canonical_chain_string": verifactu_canonical_str,
                "verifactu_sha256_fingerprint": verifactu_sha256,
                "aeat_models": ["SII Libros Registro IVA (<4 días)", "Modelo 303", "Modelo 232 (Operaciones Vinculadas)"]
            }
        }

    def calculate_mexico_sat_ift_settlement(self, credit_base_mxn: Decimal, related_uuid: str) -> tuple[dict, str]:
        """
        MÉXICO (MX):
        - IEPS Telecomunicaciones (Art. 2 Fracc. II Inciso C LIEPS): 3.00% sobre el valor del servicio.
        - IVA (Art. 1 y 12 LIVA): 16.00% calculado sobre (Base + IEPS), ya que la base del IVA
          incluye los demás impuestos que se paguen (efecto cascada legal del 19.48% total).
        - Emisión de CFDI 4.0 de Egreso (TipoDeComprobante="E", ClaveProdServ="83111600", ObjetoImp="02").
        """
        ieps_rate = Decimal("0.030000")
        iva_rate = Decimal("0.160000")

        ieps_amount = q2(credit_base_mxn * ieps_rate)
        iva_taxable_base = q2(credit_base_mxn + ieps_amount)
        iva_amount = q2(iva_taxable_base * iva_rate)
        total_traslados = q2(ieps_amount + iva_amount)
        total_cfdi_egreso = q2(credit_base_mxn + total_traslados)

        folio_uuid = str(uuid.uuid4()).upper()
        rfc_emisor = "CCG2001159A1"
        rfc_receptor = "ECI1805208B2"

        # Construcción de XML CFDI 4.0 (Anexo 20 del SAT)
        NS_CFDI = "http://www.sat.gob.mx/cfd/4"
        NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
        ET.register_namespace("cfdi", NS_CFDI)
        ET.register_namespace("xsi", NS_XSI)

        comprobante = ET.Element(
            f"{{{NS_CFDI}}}Comprobante",
            {
                f"{{{NS_XSI}}}schemaLocation": "http://www.sat.gob.mx/cfd/4 http://www.sat.gob.mx/sitio_internet/cfd/4/cfdv40.xsd",
                "Version": "4.0",
                "Serie": "NCSLA",
                "Folio": "90042",
                "Fecha": self.date_only + "T12:00:00",
                "SubTotal": str(q2(credit_base_mxn)),
                "Moneda": "MXN",
                "Total": str(total_cfdi_egreso),
                "TipoDeComprobante": "E",
                "Exportacion": "01",
                "MetodoPago": "PUE",
                "FormaPago": "17",  # 17 = Compensación (Netting Mayorista/SLA)
                "LugarExpedicion": "06600"
            }
        )

        cfdi_rel = ET.SubElement(comprobante, f"{{{NS_CFDI}}}CfdiRelacionados", {"TipoRelacion": "01"})
        ET.SubElement(cfdi_rel, f"{{{NS_CFDI}}}CfdiRelacionado", {"UUID": related_uuid})

        ET.SubElement(
            comprobante,
            f"{{{NS_CFDI}}}Emisor",
            {
                "Rfc": rfc_emisor,
                "Nombre": "CARRIER CORE GLOBAL TELECOM MEXICO SA DE CV",
                "RegimenFiscal": "601"  # General de Ley Personas Morales
            }
        )

        ET.SubElement(
            comprobante,
            f"{{{NS_CFDI}}}Receptor",
            {
                "Rfc": rfc_receptor,
                "Nombre": "ENTERPRISE CLOUD INTERCONNECT MEXICO S DE RL DE CV",
                "DomicilioFiscalReceptor": "01210",
                "RegimenFiscalReceptor": "601",
                "UsoCFDI": "G02"  # G02 = Devoluciones, descuentos o bonificaciones
            }
        )

        conceptos = ET.SubElement(comprobante, f"{{{NS_CFDI}}}Conceptos")
        concepto = ET.SubElement(
            conceptos,
            f"{{{NS_CFDI}}}Concepto",
            {
                "ClaveProdServ": "83111600",  # Servicios de telecomunicaciones de datos/enlaces
                "NoIdentificacion": "SLA-CARRIER-99999",
                "Cantidad": "1",
                "ClaveUnidad": "E48",  # Unidad de servicio
                "Unidad": "Servicio",
                "Descripcion": "Bonificacion automatica por Acuerdo de Nivel de Servicio (SLA 99.999%)",
                "ValorUnitario": str(q2(credit_base_mxn)),
                "Importe": str(q2(credit_base_mxn)),
                "ObjetoImp": "02"  # Sí objeto de impuesto
            }
        )

        imp_concepto = ET.SubElement(concepto, f"{{{NS_CFDI}}}Impuestos")
        traslados_c = ET.SubElement(imp_concepto, f"{{{NS_CFDI}}}Traslados")
        # Impuesto 003 = IEPS (3%)
        ET.SubElement(
            traslados_c,
            f"{{{NS_CFDI}}}Traslado",
            {
                "Base": str(q2(credit_base_mxn)),
                "Impuesto": "003",
                "TipoFactor": "Tasa",
                "TasaOCuota": "0.030000",
                "Importe": str(ieps_amount)
            }
        )
        # Impuesto 002 = IVA (16% sobre Base + IEPS)
        ET.SubElement(
            traslados_c,
            f"{{{NS_CFDI}}}Traslado",
            {
                "Base": str(iva_taxable_base),
                "Impuesto": "002",
                "TipoFactor": "Tasa",
                "TasaOCuota": "0.160000",
                "Importe": str(iva_amount)
            }
        )

        imp_global = ET.SubElement(
            comprobante,
            f"{{{NS_CFDI}}}Impuestos",
            {"TotalImpuestosTrasladados": str(total_traslados)}
        )
        traslados_g = ET.SubElement(imp_global, f"{{{NS_CFDI}}}Traslados")
        ET.SubElement(
            traslados_g,
            f"{{{NS_CFDI}}}Traslado",
            {
                "Base": str(q2(credit_base_mxn)),
                "Impuesto": "003",
                "TipoFactor": "Tasa",
                "TasaOCuota": "0.030000",
                "Importe": str(ieps_amount)
            }
        )
        ET.SubElement(
            traslados_g,
            f"{{{NS_CFDI}}}Traslado",
            {
                "Base": str(iva_taxable_base),
                "Impuesto": "002",
                "TipoFactor": "Tasa",
                "TasaOCuota": "0.160000",
                "Importe": str(iva_amount)
            }
        )

        # Cadena Original del Complemento de Certificación Digital del SAT
        cadena_original_sat = (
            f"||1.1|{folio_uuid}|{self.date_only}T12:00:05|SAT970701NN3|"
            f"SubTotal={q2(credit_base_mxn)}|IEPS={ieps_amount}|IVA={iva_amount}|Total={total_cfdi_egreso}|00001000000504465028||"
        )
        sello_sat_sha256 = hashlib.sha256(cadena_original_sat.encode("utf-8")).hexdigest()

        raw_xml = ET.tostring(comprobante, encoding="utf-8")
        pretty_cfdi = minidom.parseString(raw_xml).toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")

        summary = {
            "jurisdiction": "México (SAT / LFTR / IFT)",
            "regulatory_framework": {
                "nra": "Autoridad Regulatoria de Telecomunicaciones (LFTR / IFT)",
                "lawful_interception": "Art. 189 y 190 LFTR (Retención 24 meses: 12m en línea + 12m archivo y geolocalización en tiempo real)",
                "incident_reporting_sla": "Lineamientos de Fallas Masivas (< 2 horas cuando afecte >= 10,000 usuarios por > 30 min)",
                "accounting_standard": "NIF D-1 (Ingresos por contratos con clientes) y NIF D-5 (Arrendamientos)"
            },
            "tax_breakdown": {
                "currency": "MXN",
                "taxable_credit_base": str(q2(credit_base_mxn)),
                "ieps_telecom_3pct_art2_lieps": str(ieps_amount),
                "iva_taxable_base_with_ieps": str(iva_taxable_base),
                "iva_16pct_amount": str(iva_amount),
                "effective_combined_indirect_tax_pct": "19.48%",
                "total_cfdi_egreso_gross": str(total_cfdi_egreso)
            },
            "sat_cfdi40_artifact": {
                "uuid_timbre_fiscal": folio_uuid,
                "related_invoice_uuid": related_uuid,
                "tipo_comprobante": "E (Egreso)",
                "forma_pago": "17 (Compensación)",
                "uso_cfdi": "G02 (Devoluciones, descuentos o bonificaciones)",
                "cadena_original_tfd": cadena_original_sat,
                "sello_digital_sha256": sello_sat_sha256
            }
        }
        return summary, pretty_cfdi

    def calculate_colombia_dian_mintic_settlement(self, credit_base_cop: Decimal, cufe_origen: str) -> dict:
        """
        COLOMBIA (CO):
        - IVA (Art. 468 E.T.): 19.00% sobre la base gravable.
        - Impuesto Nacional al Consumo (INC - Art. 512-2 E.T.): 4.00% sobre servicios de telefonía, datos e internet móvil.
        - Contribución al Fondo Único de las TIC (FUTIC - Ley 1978 de 2019): 1.90% sobre ingresos brutos.
        - Contribución Regulatoria a la CRC: 0.15% sobre ingresos brutos.
        - Generación del CUDE (Código Único de Documento Electrónico SHA-384 - Anexo Técnico 1.9 DIAN).
        """
        iva_rate = Decimal("0.1900")
        inc_rate = Decimal("0.0400")
        futic_rate = Decimal("0.0190")
        crc_rate = Decimal("0.0015")

        iva_adj = q2(credit_base_cop * iva_rate)
        inc_adj = q2(credit_base_cop * inc_rate)
        total_taxes = q2(iva_adj + inc_adj)
        total_gross_cop = q2(credit_base_cop + total_taxes)

        futic_reduction = q2(credit_base_cop * futic_rate)
        crc_reduction = q2(credit_base_cop * crc_rate)

        num_nc = "NCSLA99001"
        nit_ofe = "900998877"
        nit_adq = "901112233"
        pin_software_dian = "75319"
        tipo_ambiente = "1"  # 1 = Producción

        # Fórmula oficial del CUDE (SHA-384) según Anexo Técnico 1.9 de la DIAN (Resolución 000165):
        # NumCr + FecCr + HorCr + ValCr + CodImp1 + ValImp1 + CodImp2 + ValImp2 + CodImp3 + ValImp3 + ValTot + NitOFE + NumAdq + PinSw + TipoAmb
        cude_composition_str = (
            f"{num_nc}{self.date_only}{self.time_only}"
            f"{q2(credit_base_cop)}"
            f"01{iva_adj}"
            f"04{inc_adj}"
            f"030.00"
            f"{total_gross_cop}"
            f"{nit_ofe}{nit_adq}{pin_software_dian}{tipo_ambiente}"
        )
        cude_sha384 = hashlib.sha384(cude_composition_str.encode("utf-8")).hexdigest()

        return {
            "jurisdiction": "Colombia (DIAN / MinTIC / CRC / ANE)",
            "regulatory_framework": {
                "nra": "Ministerio de las TIC (MinTIC), Comisión de Regulación de Comunicaciones (CRC) y ANE",
                "statute": "Ley 1341 de 2009 modificada por la Ley 1978 de 2019 y Resolución CRC 5050 de 2016",
                "lawful_interception": "Decreto 1704 de 2012 y Art. 235 CPP (Plataforma ESPERANZA - Fiscalía General de la Nación)",
                "incident_reporting_sla": "Reporte al ColCERT / CSIRT-TIC y formatos trimestrales de calidad en portal HECAA",
                "accounting_standard": "NIIF Plenas Grupo 1 (Ley 1314 de 2009 - NIIF 15 y NIIF 16)"
            },
            "tax_breakdown": {
                "currency": "COP",
                "taxable_credit_base": str(q2(credit_base_cop)),
                "iva_19pct_cod01": str(iva_adj),
                "impuesto_nacional_consumo_4pct_cod04": str(inc_adj),
                "total_credit_note_gross": str(total_gross_cop),
                "parafiscal_contributions_reversed": {
                    "futic_contraprestacion_1_90pct": str(futic_reduction),
                    "contribucion_crc_0_15pct": str(crc_reduction)
                }
            },
            "dian_ubl21_anexo19_artifact": {
                "credit_note_number": num_nc,
                "referenced_invoice_cufe": cufe_origen,
                "cude_input_string": cude_composition_str,
                "cude_sha384_signature": cude_sha384,
                "dian_concept_code": "3 (Rebaja o descuento parcial o total por SLA)"
            }
        }


def main():
    out_dir = Path(__file__).resolve().parent.parent / "output" / "jurisdictions"
    out_dir.mkdir(parents=True, exist_ok=True)

    engine = MultiJurisdictionTelcoEngine()

    # Ejecución para las 4 jurisdicciones (equivalente a una penalización SLA del 20% sobre el MRC)
    us_res = engine.calculate_us_fcc_usac_settlement(Decimal("5000.00"), is_interstate=True)
    es_res = engine.calculate_spain_aeat_cnmc_settlement(
        Decimal("5000.00"),
        previous_verifactu_hash="A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF0"
    )
    mx_res, mx_cfdi_xml = engine.calculate_mexico_sat_ift_settlement(
        Decimal("100000.00"),
        related_uuid="6B29FC40-CA47-1067-B31D-00DD010662DA"
    )
    co_res = engine.calculate_colombia_dian_mintic_settlement(
        Decimal("20000000.00"),
        cufe_origen="948c7a1b2e3f4d5c6b7a8e9f0d1c2b3a4e5f6d7c8b9a0e1f2d3c4b5a6e7f8d9c0b1a2e3f4d5c6b7a8e9f0d1c2b3a4e5f"
    )

    cfdi_path = out_dir / "mexico_cfdi40_egreso_sla.xml"
    with open(cfdi_path, "w", encoding="utf-8") as f:
        f.write(mx_cfdi_xml)

    consolidated_report = {
        "report_title": "Certificación Multi-Jurisdiccional de Gobernanza (GOV) y Fiscalidad Telecom (FIN)",
        "generated_at_utc": engine.timestamp_iso,
        "jurisdictions": {
            "US": us_res,
            "ES": es_res,
            "MX": mx_res,
            "CO": co_res
        }
    }

    report_path = out_dir / "multi_jurisdiction_gov_fin_audit.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(consolidated_report, f, indent=2, ensure_ascii=False)

    print("========================================================================================")
    print(" MOTOR REGULATORIO (GOV) Y FISCAL (FIN) EJECUTADO PARA EE. UU., ESPAÑA, MÉXICO Y COLOMBIA")
    print("========================================================================================")
    print(f"[US - FCC/USAC] Base: {us_res['tax_breakdown']['taxable_credit_base']} USD | "
          f"FET(3%)+CST+USF(34.6%): {us_res['tax_breakdown']['total_taxes_and_surcharges_reversed']} USD | "
          f"Total: {us_res['tax_breakdown']['total_credit_note_gross']} USD")
    print(f"[ES - AEAT/CNMC] Base: {es_res['tax_breakdown']['taxable_credit_base']} EUR | "
          f"IVA(21%): {es_res['tax_breakdown']['iva_21pct_adjustment']} EUR | "
          f"Huella Veri*factu: {es_res['aeat_sii_verifactu_artifact']['verifactu_sha256_fingerprint'][:24]}...")
    print(f"[MX - SAT/LFTR] Base: {mx_res['tax_breakdown']['taxable_credit_base']} MXN | "
          f"IEPS(3%): {mx_res['tax_breakdown']['ieps_telecom_3pct_art2_lieps']} MXN | "
          f"IVA(16% s/Base+IEPS): {mx_res['tax_breakdown']['iva_16pct_amount']} MXN | "
          f"Total CFDI 4.0: {mx_res['tax_breakdown']['total_cfdi_egreso_gross']} MXN")
    print(f"[CO - DIAN/CRC] Base: {co_res['tax_breakdown']['taxable_credit_base']} COP | "
          f"IVA(19%)+INC(4%): {Decimal(co_res['tax_breakdown']['iva_19pct_cod01']) + Decimal(co_res['tax_breakdown']['impuesto_nacional_consumo_4pct_cod04'])} COP | "
          f"CUDE SHA-384: {co_res['dian_ubl21_anexo19_artifact']['cude_sha384_signature'][:24]}...")
    print("----------------------------------------------------------------------------------------")
    print(f"• XML CFDI 4.0 (México) exportado en : {cfdi_path}")
    print(f"• Reporte Maestro Multi-País JSON    : {report_path}")
    print("========================================================================================")


if __name__ == "__main__":
    main()
