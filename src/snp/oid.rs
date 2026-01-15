//! SEV-SNP OID definitions for VCEK certificate extension verification.
//!
//! These OIDs are used to extract TCB values from X.509 certificate extensions
//! in AMD SEV-SNP VCEK certificates.

/// SEV-SNP OID extensions for VCEK certificate verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Oid {
    /// Boot loader SVN (1.3.6.1.4.1.3704.1.3.1)
    BootLoader,
    /// TEE SVN (1.3.6.1.4.1.3704.1.3.2)
    Tee,
    /// SNP firmware SVN (1.3.6.1.4.1.3704.1.3.3)
    Snp,
    /// Microcode SVN (1.3.6.1.4.1.3704.1.3.8)
    Ucode,
    /// Hardware ID (1.3.6.1.4.1.3704.1.4)
    HwId,
    /// FMC SVN - Turin only (1.3.6.1.4.1.3704.1.3.9)
    Fmc,
}

impl Oid {
    /// Returns the OID string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Oid::BootLoader => "1.3.6.1.4.1.3704.1.3.1",
            Oid::Tee => "1.3.6.1.4.1.3704.1.3.2",
            Oid::Snp => "1.3.6.1.4.1.3704.1.3.3",
            Oid::Ucode => "1.3.6.1.4.1.3704.1.3.8",
            Oid::HwId => "1.3.6.1.4.1.3704.1.4",
            Oid::Fmc => "1.3.6.1.4.1.3704.1.3.9",
        }
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
