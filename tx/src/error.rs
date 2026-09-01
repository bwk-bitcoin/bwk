#[derive(Debug)]
pub enum Error {
    Satisfaction,
    NoFundingTx,
    NoDescriptor,
    WrongVout,
    Update,
    Coin(bwk_coin::Error),
    /// SP output requires partial_secret but no SpPartialSecretProvider was given
    NoSpProvider,
    /// Failed to compute SP partial secret
    SpPartialSecret,
    /// Coin not found in store
    CoinNotFound,
    /// Change output already added to template
    ChangeAlreadyAdded,
}

impl From<bwk_coin::Error> for Error {
    fn from(value: bwk_coin::Error) -> Self {
        Self::Coin(value)
    }
}
