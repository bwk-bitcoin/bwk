#[derive(Debug)]
pub enum Error {
    Satisfaction,
    NoFundingTx,
    NoDescriptor,
    WrongVout,
    Update,
    Coin(bwk_coin::Error),
    /// Coin not found in store
    CoinNotFound,
    /// Change output already added to template
    ChangeAlreadyAdded,
    Input,
}

impl From<bwk_coin::Error> for Error {
    fn from(value: bwk_coin::Error) -> Self {
        Self::Coin(value)
    }
}
