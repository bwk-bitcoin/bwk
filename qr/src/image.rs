#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

impl Image {
    pub fn validate_len(&self) -> bool {
        self.width
            .checked_mul(self.height)
            .and_then(|n| usize::try_from(n).ok())
            == Some(self.data.len())
    }
}
