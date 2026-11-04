//! Errors from the BIP89 protocol and its backends.

/// Errors from the BIP89 protocol and its backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    SecretKey,
    ZeroNonce,
    HardenedIndex,
    InvalidChild,
    InvalidPoint,
    ScalarRange,
    Infinity,
    DuplicateKey,
    UnsortedBundle,
    EntryLength,
    InvalidKeychain,
    ProofLength,
    IndexRange,
    RootSignature,
    MissingRootSignature,
    NotCommitted,
    MissingTweak,
    ExtraTweak,
    SecNonceLength,
    ExtraInLength,
    TweakCount,
    NonceReuse,
    BlindSignature,
    Template,
    MissingUtxo(usize),
    MissingBundle(usize),
    InputMismatch(usize),
    OutputMismatch(usize),
    MissingProof(usize),
    Amount,
    NotParticipant,
    NothingToSign(usize),
    Psbt,
    NoTree(usize),
    /// The descriptor is not `tr()`.
    NotTaproot,
    /// A key is not a multipath extended public key.
    KeyType,
    /// A key does not have exactly two multipath elements.
    Multipath,
    /// A key does not end with an unhardened wildcard.
    Wildcard,
    /// A key has a hardened derivation step.
    HardenedStep,
    /// A base key is repeated with another chain code or path.
    ConflictingKey,
    /// The base key appears with two different chain codes.
    ConflictingChainCode([u8; 33]),
    /// The base key appears on two derivation paths that share a branch, so
    /// two of its slots would derive the same keys.
    OverlappingPaths([u8; 33]),
    /// The descriptor has no key.
    NoKeys,
    /// The base key has more than 256 slots.
    TooManySlots([u8; 33]),
    /// The slots of a base key are not numbered 0, 1, 2, ... without a gap.
    SlotGap,
}
