use bip39;
use std::fmt::Display;

#[derive(Debug, PartialEq)]
pub enum Error {
    SighashFail,
    InvalidSignature,
    InputNotOwned,
    XPrivFromSeed,
    MissingWitnessUtxo,
    SpkNotMatch,
    DerivationPath,
    Bip39(bip39::Error),
    UnregisteredDescriptor,
    DescriptorNetwork,
    Derivator,
    InputIndex,
    NotSegwit,
    NotTapKey,
    NotTapTree,
    InternalKeyNotMatch,
    InsanePrevouts,
    SigningInfo,
    InsaneTaptreeInfo,
    MixedSigningInfo,
    #[cfg(feature = "sp")]
    SpSigning,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::SighashFail => write!(f, "Sighash id not SIGHASH_ALL | SIGHASH_ANYONE_CAN_PAY"),
            Error::InvalidSignature => write!(f, "Signature processed is invalid"),
            Error::Bip39(e) => write!(f, "{e}"),
            Error::XPrivFromSeed => write!(f, "Fail to generate XPriv from seed"),
            Error::InputNotOwned => write!(f, "this input is not owned"),
            Error::MissingWitnessUtxo => write!(f, "witness_utxo field is missing in PSBT"),
            Error::SpkNotMatch => write!(f, "spk in spent output do not match"),
            Error::DerivationPath => write!(f, "Invalid derivation path"),
            Error::UnregisteredDescriptor => write!(f, "Unknown descriptor"),
            Error::DescriptorNetwork => write!(f, "Wrong descriptor network"),
            Error::Derivator => write!(f, "Fail to create derivator"),
            Error::InputIndex => write!(f, "Wrong input index"),
            Error::NotSegwit => write!(f, "This input miss segwit signing informations"),
            Error::NotTapKey => write!(f, "This input miss tap key signing informations"),
            Error::NotTapTree => write!(f, "This input miss taptree signing informations"),
            Error::InternalKeyNotMatch => write!(f, "Provided & generated internal key not match"),
            Error::InsanePrevouts => write!(f, "Insane prevouts for taproot sighash"),
            Error::SigningInfo => write!(f, "Missing signing informations"),
            Error::InsaneTaptreeInfo => write!(f, "Wrong signing informations for taptree"),
            Error::MixedSigningInfo => {
                write!(
                    f,
                    "This input mixes segwit and taproot signing informations"
                )
            }
            #[cfg(feature = "sp")]
            Error::SpSigning => write!(f, "Failed to sign SP input"),
        }
    }
}

impl From<bip39::Error> for Error {
    fn from(value: bip39::Error) -> Self {
        Error::Bip39(value)
    }
}
