use crate::{config::DecoderConfig, error::Error, image::Image, scan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    Text(String),
    /// A plain code whose payload is not UTF-8.
    Binary(Vec<u8>),
    /// A joined BBQR payload, from [`Decoder::process_raw`].
    #[cfg(feature = "bbqr")]
    Bytes(Vec<u8>),
    #[cfg(feature = "protocol")]
    Request(bipqr::ll::Request),
    #[cfg(feature = "protocol")]
    Response(bipqr::ll::Response),
}

#[cfg(feature = "protocol")]
impl From<bipqr::ll::Message> for Decoded {
    fn from(message: bipqr::ll::Message) -> Self {
        match message {
            bipqr::ll::Message::Request(request) => Self::Request(request),
            bipqr::ll::Message::Response(response) => Self::Response(response),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Decoder {
    config: DecoderConfig,
    #[cfg(feature = "bbqr")]
    joiner: bwk_bbqr::Joiner,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self::with_config(DecoderConfig::default())
    }

    pub fn with_config(config: DecoderConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "bbqr")]
            joiner: bwk_bbqr::Joiner::new(),
        }
    }

    /// Like [`Decoder::process_raw`], with a joined payload decoded as a protocol message.
    pub fn process(&mut self, image: &Image) -> Result<Option<Decoded>, Error> {
        let decoded = self.process_raw(image)?;
        #[cfg(feature = "protocol")]
        let decoded = decoded.map(decode_payload).transpose()?;
        Ok(decoded)
    }

    /// Reads the code in `image`, shrunk by
    /// [`shrink_factor`](crate::image::shrink_factor) unless [`DecoderConfig::fine_scan`]:
    /// a plain code as [`Decoded::Text`], or [`Decoded::Binary`] when not UTF-8, and a BBQR
    /// part, in hex, base32 or zlib, fed to the joiner, yielding the [`Decoded::Bytes`]
    /// payload, left undecoded, once the join completes.
    pub fn process_raw(&mut self, image: &Image) -> Result<Option<Decoded>, Error> {
        let Some(scanned) = scan::scan(image, self.config.scan_inverted, self.config.fine_scan)
        else {
            return Ok(None);
        };
        match String::from_utf8(scanned.bytes) {
            #[cfg(feature = "bbqr")]
            Ok(text) if bwk_bbqr::is_part(&text) => {
                Ok(self.joiner.add_part(&text)?.map(Decoded::Bytes))
            }
            Ok(text) => Ok(Some(Decoded::Text(text))),
            Err(e) => Ok(Some(Decoded::Binary(e.into_bytes()))),
        }
    }

    #[cfg(feature = "bbqr")]
    pub fn progress(&self) -> Option<bwk_bbqr::Progress> {
        self.joiner.progress()
    }

    pub fn reset(&mut self) {
        #[cfg(feature = "bbqr")]
        {
            self.joiner = bwk_bbqr::Joiner::new();
        }
    }
}

#[cfg(feature = "protocol")]
fn decode_payload(decoded: Decoded) -> Result<Decoded, Error> {
    match decoded {
        Decoded::Bytes(data) => Ok(bipqr::ll::decode(&data)?.into()),
        other => Ok(other),
    }
}

#[cfg(all(test, feature = "gen"))]
mod tests {
    use qrcodegen::{QrCode, QrCodeEcc};

    use crate::{
        decoder::{Decoded, Decoder},
        gen::qr_to_image,
    };

    #[test]
    fn a_plain_code_that_is_not_utf8_decodes_to_its_exact_bytes() {
        let payload = vec![0xff, 0xfe, 0x00, 0x80, b'a'];
        let code = QrCode::encode_binary(&payload, QrCodeEcc::Low).unwrap();
        let mut decoder = Decoder::new();
        assert_eq!(
            decoder.process(&qr_to_image(code)).unwrap(),
            Some(Decoded::Binary(payload))
        );
    }
}
