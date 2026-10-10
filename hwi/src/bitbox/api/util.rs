pub fn remove_leading_zeroes(list: &[u8]) -> Vec<u8> {
    if let Some(first_non_zero) = list.iter().position(|&x| x != 0) {
        list[first_non_zero..].to_vec()
    } else {
        Vec::new()
    }
}

pub trait Threading: Send + Sync {}
