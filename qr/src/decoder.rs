use crate::{config::Config, error::Error, image::Image, scan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub seen: usize,
    pub total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    Text(String),
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
    #[cfg(feature = "protocol")]
    joiner: bbqr::Joiner,
}

impl Decoder {
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.max_image_pixels == 0 {
            return Err(Error::ZeroImageLimit);
        }
        Ok(Self {
            config,
            #[cfg(feature = "protocol")]
            joiner: bbqr::Joiner::new(),
        })
    }

    pub fn process(&mut self, image: &Image) -> Result<Vec<Decoded>, Error> {
        let scanned = scan::scan(
            image,
            self.config.scan_inverted,
            self.config.max_image_pixels,
        )?;
        let mut decoded = Vec::new();
        for item in scanned {
            #[cfg(feature = "protocol")]
            if bbqr::is_part(&item.text) {
                if let Some(data) = self
                    .joiner
                    .add_part(&item.text, self.config.max_message_bytes)?
                {
                    decoded.push(crate::protocol::decode(&data)?.into());
                }
                continue;
            }
            decoded.push(Decoded::Text(item.text));
        }
        Ok(decoded)
    }

    pub fn progress(&self) -> Option<Progress> {
        #[cfg(feature = "protocol")]
        {
            self.joiner.progress().map(|progress| Progress {
                seen: progress.seen,
                total: progress.total,
            })
        }
        #[cfg(not(feature = "protocol"))]
        {
            None
        }
    }

    pub fn reset(&mut self) {
        #[cfg(feature = "protocol")]
        {
            self.joiner = bbqr::Joiner::new();
        }
    }
}
