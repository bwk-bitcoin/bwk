use crate::{config::Config, error::Error, gen, image::Image};

#[derive(Debug, Clone)]
pub struct Encoder {
    config: Config,
}

impl Encoder {
    pub fn new(config: Config) -> Result<Self, Error> {
        if !(1..=40).contains(&config.max_qr_version) {
            return Err(Error::QrVersion(config.max_qr_version));
        }
        if config.bbqr_part_bytes == 0 {
            return Err(Error::ZeroPartSize);
        }
        #[cfg(feature = "protocol")]
        {
            // parts render at a pinned version, so a full-size one must fit it
            let probe = bbqr::split(&vec![0; config.bbqr_part_bytes], config.bbqr_part_bytes)?;
            for part in &probe.parts {
                if gen::encode_alphanumeric(part, config.max_qr_version).is_err() {
                    return Err(Error::PartTooLarge {
                        bytes: config.bbqr_part_bytes,
                        version: config.max_qr_version,
                    });
                }
            }
        }
        Ok(Self { config })
    }

    pub fn encode_text(&self, text: &str) -> Result<Image, Error> {
        gen::encode_text(text, gen::CorrectionLevel::Low, self.config.max_qr_version)
    }

    #[cfg(feature = "protocol")]
    pub fn encode_request(&self, request: &crate::protocol::Request) -> Result<Vec<Image>, Error> {
        self.encode_protocol(&crate::protocol::encode_request(request)?)
    }

    #[cfg(feature = "protocol")]
    pub fn encode_response(
        &self,
        response: &crate::protocol::Response,
    ) -> Result<Vec<Image>, Error> {
        self.encode_protocol(&crate::protocol::encode_response(response)?)
    }

    #[cfg(feature = "protocol")]
    fn encode_protocol(&self, data: &[u8]) -> Result<Vec<Image>, Error> {
        let split = bbqr::split(data, self.config.bbqr_part_bytes)?;
        split
            .parts
            .iter()
            .map(|part| gen::encode_alphanumeric(part, self.config.max_qr_version))
            .collect()
    }
}
