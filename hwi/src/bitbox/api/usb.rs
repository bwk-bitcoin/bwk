use super::constants::{PRODUCT_ID, VENDOR_ID};
use std::sync::Mutex;
use thiserror::Error;

use super::communication::{Error as CommunicationError, ReadWrite};

const FIRMWARE_PRODUCT_STRING_BITBOX02_MULTI: &str = "BitBox02";
const FIRMWARE_PRODUCT_STRING_BITBOX02_BTCONLY: &str = "BitBox02BTC";
const FIRMWARE_PRODUCT_STRING_BITBOX02_NOVA_MULTI: &str = "BitBox02 Nova Multi";
const FIRMWARE_PRODUCT_STRING_BITBOX02_NOVA_BTCONLY: &str = "BitBox02 Nova BTC-only";

pub(crate) struct HidDevice(Mutex<hidapi::HidDevice>);

impl crate::bitbox::api::util::Threading for HidDevice {}

impl HidDevice {
    pub(crate) fn new(device: hidapi::HidDevice) -> Self {
        HidDevice(Mutex::new(device))
    }

    fn get(&self) -> std::sync::MutexGuard<'_, hidapi::HidDevice> {
        self.0.lock().unwrap()
    }
}

impl ReadWrite for HidDevice {
    fn write(&self, msg: &[u8]) -> Result<usize, CommunicationError> {
        let device = self.get();
        let mut v = vec![0x00];
        v.extend_from_slice(msg);
        #[allow(clippy::needless_borrow)]
        hidapi::HidDevice::write(&device, &v).or(Err(CommunicationError::Write))
    }

    fn read(&self) -> Result<Vec<u8>, CommunicationError> {
        let device = self.get();
        let mut buf = [0u8; 64];
        #[allow(clippy::needless_borrow)]
        let res = hidapi::HidDevice::read(&device, &mut buf).or(Err(CommunicationError::Read))?;
        Ok(buf[..res].to_vec())
    }
}

#[derive(Error, Debug)]
pub enum UsbError {
    #[error("hid error: {0}")]
    Hid(#[from] hidapi::HidError),
    #[error("could not find device or device is busy")]
    NotFound,
}

/// Returns true if this device is a BitBox02 device (any edition). This does not identify BitBox02
/// bootloaders.
pub fn is_bitbox02(device_info: &hidapi::DeviceInfo) -> bool {
    (matches!(
        device_info.product_string(),
        Some(
            FIRMWARE_PRODUCT_STRING_BITBOX02_MULTI
                | FIRMWARE_PRODUCT_STRING_BITBOX02_BTCONLY
                | FIRMWARE_PRODUCT_STRING_BITBOX02_NOVA_MULTI
                | FIRMWARE_PRODUCT_STRING_BITBOX02_NOVA_BTCONLY
        )
    )) && device_info.vendor_id() == VENDOR_ID
        && device_info.product_id() == PRODUCT_ID
        && (device_info.usage_page() == 0xffff || device_info.interface_number() == 0)
}

/// Returns the first BitBox02 HID device info that is found, or `Err(UsbError::NotFound)` if none
/// is available.
pub fn get_any_bitbox02() -> Result<hidapi::HidDevice, UsbError> {
    let api = hidapi::HidApi::new().unwrap();
    for device_info in api.device_list() {
        if is_bitbox02(device_info) {
            return Ok(device_info.open_device(&api)?);
        }
    }
    Err(UsbError::NotFound)
}
