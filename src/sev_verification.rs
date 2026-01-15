//! WASM-only AMD SEV-SNP Attestation Verification
//!
//! This implementation is designed to be compiled only for wasm32 and uses
//! wasm-bindgen for fetching KDS artifacts via an extension-provided JS bridge.
use crate::certificate_chain::AmdCertificates;
use crate::crypto::{Certificate, CertificateExt};
use crate::snp::Oid;
use crate::Result;
use crate::{snp, AttestationReport};

use asn1_rs::FromBer;
use log::{error, info};

/// Result of AMD SEV-SNP attestation verification
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SevVerificationResult {
    /// Whether the attestation passed all verification checks
    pub is_valid: bool,
    /// Detailed verification status for each component
    pub details: SevVerificationDetails,
    /// Error messages if verification failed
    pub errors: Vec<String>,
}

/// Detailed verification results for AMD SEV-SNP attestation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SevVerificationDetails {
    /// Whether the processor model was identified successfully
    pub processor_identified: bool,
    /// Whether AMD certificates were fetched successfully  
    pub certificates_fetched: bool,
    /// Whether the certificate chain is valid (ARK -> ASK -> VCEK)
    pub certificate_chain_valid: bool,
    /// Whether the attestation signature is valid
    pub signature_valid: bool,
    /// Whether TCB values match certificate extensions
    pub tcb_valid: bool,
    /// Processor model identified from the attestation report
    pub processor_model: Option<String>,
}

/// WASM SEV verifier (only compiled for wasm32)
pub struct SevVerifier {
    amd_certificates: AmdCertificates,
}

impl SevVerifier {
    pub async fn new() -> Result<Self> {
        #[cfg(target_arch = "wasm32")]
        Self::init_wasm_logging();
        let amd_certificates = AmdCertificates::new().await?;
        Ok(Self { amd_certificates })
    }

    pub async fn with_cache() -> Result<Self> {
        #[cfg(target_arch = "wasm32")]
        Self::init_wasm_logging();
        let amd_certificates = AmdCertificates::with_cache(true).await?;
        Ok(Self { amd_certificates })
    }

    #[cfg(target_arch = "wasm32")]
    /// Initialize wasm logging and panic hook once. Only available when the
    /// `wasm` feature is enabled. No-op on non-wasm builds or when the feature
    /// isn't enabled.
    fn init_wasm_logging() {
        {
            static INIT: std::sync::Once = std::sync::Once::new();
            INIT.call_once(|| {
                // Route panics to console.error
                console_error_panic_hook::set_once();
                // Initialize the wasm logger to forward `log` records to console.log
                wasm_logger::init(wasm_logger::Config::new(log::Level::Info));
            });
        }
    }

    pub async fn verify_attestation(
        &mut self,
        attestation_report: &AttestationReport,
    ) -> Result<SevVerificationResult> {
        let mut result = SevVerificationResult {
            is_valid: false,
            details: SevVerificationDetails {
                processor_identified: false,
                certificates_fetched: false,
                certificate_chain_valid: false,
                signature_valid: false,
                tcb_valid: false,
                processor_model: None,
            },
            errors: Vec::new(),
        };

        // Step 1: Identify processor model
        let processor_model = snp::model::Generation::from_family_and_model(
            attestation_report.cpuid_fam_id,
            attestation_report.cpuid_mod_id,
        );
        if processor_model.is_err() {
            let error = format!(
                "Unsupported processor family/model: {} / {}",
                attestation_report.cpuid_fam_id, attestation_report.cpuid_mod_id
            );
            result.errors.push(error.clone());
            error!("{}", error);
            return Ok(result);
        }

        let processor_model = processor_model.unwrap();
        result.details.processor_identified = true;
        result.details.processor_model = Some(processor_model.to_string());

        // Step 2: Get VCEK certificate for this processor (includes chain verification)
        let vcek = match self
            .amd_certificates
            .get_vcek(processor_model, attestation_report)
            .await
        {
            Ok(cert) => {
                result.details.certificates_fetched = true;
                result.details.certificate_chain_valid = true;
                info!("VCEK certificate fetched and verified successfully");
                cert
            }
            Err(e) => {
                let msg = format!("Failed to fetch/verify VCEK certificate: {}", e);
                result.errors.push(msg.clone());
                error!("{}", msg);
                return Ok(result);
            }
        };

        // Step 3: Verify attestation signature
        if let Err(e) = Self::verify_attestation_signature(attestation_report, &vcek) {
            let msg = format!("Signature verification failed: {}", e);
            result.errors.push(msg.clone());
            error!("{}", msg);
            return Ok(result);
        }
        result.details.signature_valid = true;

        // Step 4: Verify TCB values
        if let Err(e) = Self::verify_tcb_values(&vcek, attestation_report) {
            let msg = format!("TCB verification failed: {}", e);
            result.errors.push(msg.clone());
            error!("{}", msg);
            return Ok(result);
        }
        result.details.tcb_valid = true;

        result.is_valid = true;
        if result.is_valid {
            info!("AMD SEV-SNP verification PASSED");
        } else {
            error!("AMD SEV-SNP verification FAILED: {:?}", result.errors);
        }
        Ok(result)
    }

    fn verify_attestation_signature(
        attestation_report: &AttestationReport,
        vcek: &Certificate,
    ) -> Result<()> {
        use crate::crypto::Verifier;
        vcek.verify(attestation_report)
            .map_err(|e| format!("Failed to verify attestation signature: {}", e).into())
    }

    fn verify_tcb_values(vcek: &Certificate, attestation_report: &AttestationReport) -> Result<()> {
        // Helper to check extension value (handles different ASN.1 wrapping)
        let check_ext_u8 = |oid: Oid, expected: u8| -> Result<()> {
            let ext_value = vcek
                .get_extension_by_oid(oid.as_str())
                .map_err(|e| format!("Failed to get extension {}: {}", oid.as_str(), e))?;
            let ext_u8 = asn1_rs::Integer::from_ber(&ext_value)
                .and_then(|(_, int)| Ok(int.as_u8()?))
                .map_err(|e| {
                    format!(
                        "Failed to parse {:02x?} from extension {} as u8: {}",
                        ext_value,
                        oid.as_str(),
                        e
                    )
                })?;

            if ext_u8 == expected {
                Ok(())
            } else {
                Err(format!("Value mismatch: cert={} report={}", ext_u8, expected).into())
            }
        };

        let gen = snp::model::Generation::from_family_and_model(
            attestation_report.cpuid_fam_id,
            attestation_report.cpuid_mod_id,
        )?;
        match gen {
            snp::model::Generation::Milan | snp::model::Generation::Genoa => {
                let tcb = attestation_report.reported_tcb.as_milan_genoa();
                check_ext_u8(Oid::BootLoader, tcb.boot_loader)
                    .map_err(|e| format!("Error verifying TCB boot loader: {}", e))?;
                check_ext_u8(Oid::Tee, tcb.tee)
                    .map_err(|e| format!("Error verifying TCB TEE: {}", e))?;
                check_ext_u8(Oid::Snp, tcb.snp)
                    .map_err(|e| format!("Error verifying TCB SNP: {}", e))?;
                check_ext_u8(Oid::Ucode, tcb.microcode)
                    .map_err(|e| format!("Error verifying TCB microcode: {}", e))?;
            }
            snp::model::Generation::Turin => {
                let tcb = attestation_report.reported_tcb.as_turin();
                check_ext_u8(Oid::BootLoader, tcb.boot_loader)
                    .map_err(|e| format!("Error verifying TCB boot loader: {}", e))?;
                check_ext_u8(Oid::Tee, tcb.tee)
                    .map_err(|e| format!("Error verifying TCB TEE: {}", e))?;
                check_ext_u8(Oid::Snp, tcb.snp)
                    .map_err(|e| format!("Error verifying TCB SNP: {}", e))?;
                check_ext_u8(Oid::Ucode, tcb.microcode)
                    .map_err(|e| format!("Error verifying TCB microcode: {}", e))?;
                check_ext_u8(Oid::Fmc, tcb.fmc)
                    .map_err(|e| format!("Error verifying TCB FMC: {}", e))?;
            }
        }

        let attestation_hwid: Result<&[u8]> = match gen {
            snp::model::Generation::Turin => {
                if attestation_report.chip_id[0x8..].iter().any(|&b| b != 0) {
                    Err(
                        "Invalid HWID in attestation report for Turin: upper bytes must be zero"
                            .into(),
                    )
                } else {
                    Ok(&attestation_report.chip_id[0..0x8])
                }
            }
            snp::model::Generation::Milan | snp::model::Generation::Genoa => {
                Ok(&attestation_report.chip_id[..])
            }
        };
        let attestation_hwid = attestation_hwid?;

        let extension_hwid = vcek
            .get_extension_by_oid(Oid::HwId.as_str())
            .map_err(|e| format!("Failed to get extension {}: {}", Oid::HwId.as_str(), e))?;

        if extension_hwid != attestation_hwid {
            let extension_hwid_ber =
                asn1_rs::OctetString::from_ber(&extension_hwid).map_err(|e| {
                    format!(
                        "Failed to parse HWID from extension {} as octet string: {}",
                        Oid::HwId.as_str(),
                        e
                    )
                })?;
            if extension_hwid_ber.0 != attestation_hwid {
                return Err(format!(
                    "HWID mismatch: cert={:x?} report={:x?}",
                    extension_hwid_ber.0, attestation_hwid
                )
                .into());
            }
        }
        Ok(())
    }
}
