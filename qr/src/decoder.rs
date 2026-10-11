use crate::{config::Config, error::Error, image::Image, scan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub seen: usize,
    pub total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    Text(String),
    /// A joined BBQR payload, from [`Decoder::process_raw`].
    #[cfg(feature = "bbqr")]
    Bytes(Vec<u8>),
    #[cfg(feature = "protocol")]
    Request(crate::protocol::Request),
    #[cfg(feature = "protocol")]
    Response(crate::protocol::Response),
}

#[cfg(feature = "protocol")]
impl From<crate::protocol::Message> for Decoded {
    fn from(message: crate::protocol::Message) -> Self {
        match message {
            crate::protocol::Message::Request(request) => Self::Request(request),
            crate::protocol::Message::Response(response) => Self::Response(response),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Decoder {
    config: Config,
    #[cfg(feature = "bbqr")]
    joiner: bbqr::Joiner,
}

impl Decoder {
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.max_image_pixels == 0 {
            return Err(Error::ZeroImageLimit);
        }
        Ok(Self {
            config,
            #[cfg(feature = "bbqr")]
            joiner: bbqr::Joiner::new(),
        })
    }

    /// Like [`Decoder::process_raw`], with each joined payload decoded as a protocol
    /// message.
    pub fn process(&mut self, image: &Image) -> Result<Vec<Decoded>, Error> {
        let decoded = self.process_raw(image)?;
        #[cfg(feature = "protocol")]
        let decoded = decoded
            .into_iter()
            .map(decode_payload)
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(decoded)
    }

    /// Reads the codes in `image`: plain codes as [`Decoded::Text`], and BBQR parts
    /// joined, once complete, into a [`Decoded::Bytes`] payload left undecoded.
    pub fn process_raw(&mut self, image: &Image) -> Result<Vec<Decoded>, Error> {
        let scanned = scan::scan(
            image,
            self.config.scan_inverted,
            self.config.max_image_pixels,
        )?;
        let mut decoded = Vec::new();
        for item in scanned {
            #[cfg(feature = "bbqr")]
            if bbqr::is_part(&item.text) {
                if let Some(data) = self
                    .joiner
                    .add_part(&item.text, self.config.max_message_bytes)?
                {
                    decoded.push(Decoded::Bytes(data));
                }
                continue;
            }
            decoded.push(Decoded::Text(item.text));
        }
        Ok(decoded)
    }

    pub fn progress(&self) -> Option<Progress> {
        #[cfg(feature = "bbqr")]
        {
            self.joiner.progress().map(|progress| Progress {
                seen: progress.seen,
                total: progress.total,
            })
        }
        #[cfg(not(feature = "bbqr"))]
        {
            None
        }
    }

    pub fn reset(&mut self) {
        #[cfg(feature = "bbqr")]
        {
            self.joiner = bbqr::Joiner::new();
        }
    }
}

#[cfg(feature = "protocol")]
fn decode_payload(decoded: Decoded) -> Result<Decoded, Error> {
    match decoded {
        Decoded::Bytes(data) => Ok(crate::protocol::decode(&data)?.into()),
        other => Ok(other),
    }
}
