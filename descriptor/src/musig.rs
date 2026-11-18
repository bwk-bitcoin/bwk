//! BIP-390 musig() descriptors: parse through the token form, print standard.

use std::str::FromStr;

use bwk_keys::{
    keys::OXpub,
    musig::{DefiniteMusigKey, MusigKey, MUSIG_TOKEN_PREFIX, MUSIG_TOKEN_SEPARATOR},
};
use miniscript::{descriptor::checksum::desc_checksum, ForEachKey};

use crate::descriptor::Error;

pub type MusigDescriptor = miniscript::Descriptor<MusigKey>;
pub type DefiniteMusigDescriptor = miniscript::Descriptor<DefiniteMusigKey>;

/// Start of a musig() expression in the standard BIP-390 text.
const BIP390_PREFIX: &str = "musig(";

/// Characters miniscript splits on: they end a musig token.
const TOKEN_END: [char; 5] = [',', '(', ')', '{', '}'];

fn parse_error(message: &str) -> Error {
    Error::Parse(message.into())
}

/// Checks the checksum, rewrites to the token form, parses, enforces musig() in tr() only.
/// Leading and trailing whitespace is trimmed first.
pub fn parse_musig_descriptor(s: &str) -> Result<MusigDescriptor, Error> {
    let s = s.trim();
    let body = match s.rsplit_once('#') {
        Some((body, checksum)) => {
            let expected = desc_checksum(body).map_err(|e| Error::Parse(e.to_string()))?;
            if expected != checksum {
                return Err(parse_error("invalid checksum"));
            }
            body
        }
        None => s,
    };
    let descriptor = MusigDescriptor::from_str(&to_token_form(body)?)
        .map_err(|e| Error::Parse(e.to_string()))?;
    // miniscript 12 has no rawtr() and bwk parses sp() elsewhere: tr() is the
    // only place BIP-390 allows that is left.
    if !matches!(descriptor, miniscript::Descriptor::Tr(_))
        && descriptor.for_any_key(MusigKey::is_musig)
    {
        return Err(Error::MusigOutsideTr);
    }
    Ok(descriptor)
}

/// Standard BIP-390 text, with its checksum when `checksum`.
pub fn musig_descriptor_to_string(descriptor: &MusigDescriptor, checksum: bool) -> String {
    let body = to_bip390_form(&format!("{descriptor:#}"));
    if checksum {
        let checksum = desc_checksum(&body).expect("printable descriptor");
        format!("{body}#{checksum}")
    } else {
        body
    }
}

/// `musig(K1,...,Kn)` to `musig|K1|...|Kn|`, everything else verbatim, no checksum.
pub fn to_token_form(s: &str) -> Result<String, Error> {
    if s.contains('#') {
        return Err(parse_error("checksum not expected"));
    }
    let mut token_form = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find(BIP390_PREFIX) {
        token_form.push_str(&rest[..start]);
        let inner = &rest[start + BIP390_PREFIX.len()..];
        // Keys never hold parentheses: the first `)` closes the expression.
        let close = inner.find(')').ok_or(parse_error("unclosed musig()"))?;
        let keys = &inner[..close];
        if keys.contains('(') {
            return Err(parse_error("nested expression in musig()"));
        }
        token_form.push_str(MUSIG_TOKEN_PREFIX);
        for key in keys.split(',') {
            if key.is_empty() {
                return Err(parse_error("empty key in musig()"));
            }
            token_form.push_str(key);
            token_form.push(MUSIG_TOKEN_SEPARATOR);
        }
        rest = &inner[close + 1..];
    }
    token_form.push_str(rest);
    Ok(token_form)
}

/// The inverse of `to_token_form`.
pub fn to_bip390_form(s: &str) -> String {
    let mut bip390_form = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find(MUSIG_TOKEN_PREFIX) {
        bip390_form.push_str(&rest[..start]);
        let token = &rest[start + MUSIG_TOKEN_PREFIX.len()..];
        let end = token.find(TOKEN_END).unwrap_or(token.len());
        match token[..end].rsplit_once(MUSIG_TOKEN_SEPARATOR) {
            Some((keys, suffix)) => {
                bip390_form.push_str(BIP390_PREFIX);
                bip390_form.push_str(&keys.replace(MUSIG_TOKEN_SEPARATOR, ","));
                bip390_form.push(')');
                bip390_form.push_str(suffix);
            }
            // Not a token `MusigKey` printed: left as is.
            None => bip390_form.push_str(&rest[start..start + MUSIG_TOKEN_PREFIX.len() + end]),
        }
        rest = &token[end..];
    }
    bip390_form.push_str(rest);
    bip390_form
}

/// `tr(musig(cosigners...)/<0;1>/*)`, key path only, cosigners in the given order.
pub fn musig_tr(cosigners: &[OXpub]) -> Result<MusigDescriptor, Error> {
    if cosigners.is_empty() {
        return Err(parse_error("musig() needs cosigners"));
    }
    let keys: Vec<String> = cosigners
        .iter()
        .map(|x| format!("[{}/{}]{}", x.origin.0, x.origin.1, x.xkey))
        .collect();
    parse_musig_descriptor(&format!("tr(musig({})/<0;1>/*)", keys.join(",")))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bwk_keys::keys::OXpub;
    use miniscript::{
        bitcoin::bip32::{DerivationPath, Fingerprint, Xpub},
        descriptor::checksum::desc_checksum,
    };

    use crate::{
        descriptor::Error,
        musig::{
            musig_descriptor_to_string, musig_tr, parse_musig_descriptor, to_bip390_form,
            to_token_form,
        },
    };

    // BIP-390 test vector xpubs (mainnet).
    const X1: &str = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
    const X2: &str = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y";
    const X3: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    fn key_path_musig() -> String {
        format!("tr(musig([aabbccdd/87'/0'/0']{X1},[11223344/87h/0h/0h]{X2})/<0;1>/*)")
    }

    #[test]
    fn token_form_round_trips() {
        let cases = [
            key_path_musig(),
            format!("tr({X3}/<0;1>/*,{{pk(musig({X1},{X2})/<0;1>/*),pk({X3}/<2;3>/*)}})"),
            format!("tr({X3}/<0;1>/*,{{pk(musig({X1},{X2})/0/*),pk(musig({X2},{X3}))}})"),
            format!("tr([aabbccdd/86'/0'/0']{X3}/<0;1>/*)"),
        ];
        for s in cases {
            let token = to_token_form(&s).unwrap();
            assert!(!token.contains("musig("));
            assert_eq!(to_bip390_form(&token), s);
        }
        assert_eq!(
            to_token_form(&key_path_musig()).unwrap(),
            format!("tr(musig|[aabbccdd/87'/0'/0']{X1}|[11223344/87h/0h/0h]{X2}|/<0;1>/*)")
        );
    }

    #[test]
    fn to_token_form_rejects_malformed_musig() {
        for s in ["tr(musig(A,B", "tr(musig(A,,B))", "tr(musig(musig(A,B),C))"] {
            assert!(matches!(to_token_form(s), Err(Error::Parse(_))));
        }
        assert!(matches!(
            to_token_form("tr(musig(A,B))#abcdefgh"),
            Err(Error::Parse(_))
        ));
    }

    #[test]
    fn standard_print_round_trips_with_checksum() {
        let d = parse_musig_descriptor(&key_path_musig()).unwrap();
        let printed = musig_descriptor_to_string(&d, true);
        assert!(printed.contains("musig("));
        let (body, checksum) = printed.rsplit_once('#').unwrap();
        assert_eq!(checksum.len(), 8);
        assert_eq!(checksum, desc_checksum(body).unwrap());
        assert_eq!(parse_musig_descriptor(&printed).unwrap(), d);
        assert_eq!(musig_descriptor_to_string(&d, false), body);
    }

    #[test]
    fn bad_checksum_is_refused() {
        let d = parse_musig_descriptor(&key_path_musig()).unwrap();
        let printed = musig_descriptor_to_string(&d, true);
        let last = printed.chars().last().unwrap();
        let swapped = if last == 'q' { 'p' } else { 'q' };
        let tampered = format!("{}{swapped}", &printed[..printed.len() - 1]);
        assert!(matches!(
            parse_musig_descriptor(&tampered),
            Err(Error::Parse(_))
        ));
    }

    #[test]
    fn musig_tr_builds_key_path_descriptor() {
        let oxpub = |fingerprint: &str, xpub: &str| OXpub {
            origin: (
                Fingerprint::from_str(fingerprint).unwrap(),
                DerivationPath::from_str("m/87'/0'/0'").unwrap(),
            ),
            xkey: Xpub::from_str(xpub).unwrap(),
        };
        let d = musig_tr(&[oxpub("aabbccdd", X2), oxpub("11223344", X1)]).unwrap();
        assert_eq!(
            musig_descriptor_to_string(&d, false),
            format!("tr(musig([aabbccdd/87'/0'/0']{X2},[11223344/87'/0'/0']{X1})/<0;1>/*)")
        );
        assert!(matches!(musig_tr(&[]), Err(Error::Parse(_))));
    }
}
