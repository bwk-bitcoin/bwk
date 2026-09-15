pub mod command {
    use bitcoin::{hashes::hex::FromHex, Network};
    use bwk_hwi::{
        bitbox::{BitBox02, PairingBitbox02WithLocalCache},
        coldcard,
        jade::{self, Jade},
        ledger::{hidapi::HidApi, Ledger, LedgerSimulator, TransportHID},
        specter::{Specter, SpecterSimulator},
        HWI,
    };
    use std::error::Error;

    pub struct Wallet<'a> {
        pub name: Option<&'a String>,
        pub policy: Option<&'a String>,
        pub hmac: Option<&'a String>,
    }

    pub fn list(
        network: Network,
        wallet: Option<Wallet<'_>>,
    ) -> Result<Vec<Box<dyn HWI + Send>>, Box<dyn Error>> {
        let mut hws = Vec::new();

        if let Ok(device) = SpecterSimulator::try_connect() {
            hws.push(device.into());
        }

        if let Ok(devices) = Specter::enumerate() {
            for device in devices {
                hws.push(device.into());
            }
        }

        match Jade::enumerate() {
            Err(e) => println!("{e:?}"),
            Ok(devices) => {
                for device in devices {
                    let device = device.with_network(network);
                    if let Ok(info) = device.get_info() {
                        if info.jade_state == jade::api::JadeState::Locked {
                            if let Err(e) = device.auth() {
                                eprintln!("auth {e:?}");
                                continue;
                            }
                        }

                        hws.push(device.into());
                    }
                }
            }
        }

        if let Ok(device) = LedgerSimulator::try_connect() {
            hws.push(device.into());
        }

        let api = Box::new(HidApi::new().unwrap());

        for device_info in api.device_list() {
            if bwk_hwi::bitbox::api::usb::is_bitbox02(device_info) {
                if let Ok(device) = device_info.open_device(&api) {
                    if let Ok(device) = PairingBitbox02WithLocalCache::connect(device, None) {
                        if let Ok((device, _)) = device.wait_confirm() {
                            let mut bb02 = BitBox02::from(device).with_network(network);
                            if let Some(policy) = wallet.as_ref().and_then(|w| w.policy) {
                                bb02 = bb02.with_policy(policy)?;
                            }
                            hws.push(bb02.into());
                        }
                    }
                }
            }
            if device_info.vendor_id() == coldcard::api::COINKITE_VID
                && device_info.product_id() == coldcard::api::CKCC_PID
            {
                if let Some(sn) = device_info.serial_number() {
                    if let Ok((cc, _)) = coldcard::api::Coldcard::open(&api, sn, None) {
                        let mut hw = coldcard::Coldcard::from(cc);
                        if let Some(ref wallet) = wallet {
                            hw = hw.with_wallet_name(
                                wallet
                                    .name
                                    .ok_or::<Box<dyn Error>>(
                                        "coldcard requires a wallet name".into(),
                                    )?
                                    .to_string(),
                            );
                        }
                        hws.push(hw.into())
                    }
                }
            }
        }

        for detected in Ledger::<TransportHID>::enumerate(&api) {
            if let Ok(mut device) = Ledger::<TransportHID>::connect(&api, detected) {
                if let Some(ref wallet) = wallet {
                    let hmac = if let Some(s) = wallet.hmac {
                        let mut h = [b'\0'; 32];
                        h.copy_from_slice(&Vec::from_hex(s)?);
                        Some(h)
                    } else {
                        None
                    };
                    device = device.with_wallet(
                        wallet
                            .name
                            .ok_or::<Box<dyn Error>>("ledger requires a wallet name".into())?,
                        wallet
                            .policy
                            .ok_or::<Box<dyn Error>>("ledger requires a wallet policy".into())?,
                        hmac,
                    )?;
                }
                hws.push(device.into());
            }
        }

        Ok(hws)
    }
}
