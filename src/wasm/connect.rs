// SPDX-License-Identifier: Apache-2.0

use super::{noise, types::TsOnCloseCb, BitBox, Bootloader, JavascriptError};
use crate::communication;
use wasm_bindgen::prelude::*;

struct JsReadWrite {
    write_function: js_sys::Function,
    read_function: js_sys::Function,
}

impl crate::util::Threading for JsReadWrite {}

#[wasm_bindgen(raw_module = "./webhid.js")]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn getWebHIDDevice(
        vendorId: f64,
        productId: f64,
        onCloseCb: TsOnCloseCb,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    async fn getBridgeDevice(onCloseCb: TsOnCloseCb) -> Result<JsValue, JsValue>;

    fn hasWebHID() -> bool;
}

#[async_trait::async_trait(?Send)]
impl communication::ReadWrite for JsReadWrite {
    fn write(&self, msg: &[u8]) -> Result<usize, communication::Error> {
        self.write_function
            .call1(&JsValue::NULL, &js_sys::Uint8Array::from(msg))
            .map_err(|_| communication::Error::Write)?;
        Ok(msg.len())
    }

    async fn read(&self) -> Result<Vec<u8>, communication::Error> {
        let result = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(
            self.read_function
                .call0(&JsValue::NULL)
                .map_err(|_| communication::Error::Read)?,
        ))
        .await
        .unwrap();
        Ok(js_sys::Uint8Array::from(result).to_vec())
    }
}

struct JsDevice {
    read_write: Box<JsReadWrite>,
    close_function: js_sys::Function,
    /// HID product string, empty for the BitBoxBridge, which does not report one.
    product_name: String,
}

fn get_js_device(result: &JsValue) -> Result<JsDevice, JavascriptError> {
    let write_function: js_sys::Function = js_sys::Reflect::get(result, &"write".into())
        .or(Err(JavascriptError::InvalidType("`write` key missing")))?
        .dyn_into()
        .or(Err(JavascriptError::InvalidType(
            "`write` object is not a function",
        )))?;
    let read_function: js_sys::Function = js_sys::Reflect::get(result, &"read".into())
        .or(Err(JavascriptError::InvalidType("`read` key missing")))?
        .dyn_into()
        .or(Err(JavascriptError::InvalidType(
            "`read` object is not a function",
        )))?;
    let close_function: js_sys::Function = js_sys::Reflect::get(result, &"close".into())
        .or(Err(JavascriptError::InvalidType("`close` key missing")))?
        .dyn_into()
        .or(Err(JavascriptError::InvalidType(
            "`close` object is not a function",
        )))?;
    let product_name = js_sys::Reflect::get(result, &"productName".into())
        .ok()
        .and_then(|value| value.as_string())
        .unwrap_or_default();

    Ok(JsDevice {
        read_write: Box::new(JsReadWrite {
            write_function,
            read_function,
        }),
        close_function,
        product_name,
    })
}

/// An open WebHID connection to a BitBox02 whose mode is not yet decided. A device with firmware
/// enumerates as `BitBox02…` and is used through `intoBitBox()`; a device without firmware, or one
/// rebooted into its bootloader, enumerates as `…bootloader`/`… bl` and is used through
/// `intoBootloader()`. The two speak different protocols, so the wrong conversion is refused
/// rather than attempted: talking firmware protocol to a bootloader stalls forever waiting for an
/// answer that never comes.
#[wasm_bindgen]
pub struct Connection {
    device: Option<JsDevice>,
}

#[wasm_bindgen]
impl Connection {
    /// The HID product string the device enumerated with.
    #[wasm_bindgen(js_name = productName)]
    pub fn product_name(&self) -> String {
        self.device
            .as_ref()
            .map(|d| d.product_name.clone())
            .unwrap_or_default()
    }

    /// True if the device is running its bootloader instead of firmware.
    #[wasm_bindgen(js_name = isBootloader)]
    pub fn is_bootloader(&self) -> bool {
        crate::bootloader::is_bootloader_product_string(&self.product_name())
    }

    /// Continue in firmware mode. Fails with code `bootloader-mode` if the device is a bootloader.
    #[wasm_bindgen(js_name = intoBitBox)]
    pub async fn into_bitbox(mut self) -> Result<BitBox, JavascriptError> {
        let device = self.device.take().ok_or(JavascriptError::Unknown)?;
        if crate::bootloader::is_bootloader_product_string(&device.product_name) {
            let _ = device.close_function.call0(&JsValue::NULL);
            return Err(JavascriptError::BootloaderMode);
        }
        let communication = Box::new(communication::U2fHidCommunication::from(
            device.read_write,
            communication::FIRMWARE_CMD,
        ));
        Ok(BitBox {
            device: crate::BitBox::from(communication, Box::new(noise::LocalStorageNoiseConfig {}))
                .await?,
            close_function: device.close_function,
        })
    }

    /// Continue in bootloader mode. Fails with code `not-bootloader` if the device runs firmware.
    #[wasm_bindgen(js_name = intoBootloader)]
    pub fn into_bootloader(mut self) -> Result<Bootloader, JavascriptError> {
        let device = self.device.take().ok_or(JavascriptError::Unknown)?;
        let product =
            match crate::bootloader::BootloaderProduct::from_product_string(&device.product_name) {
                Some(product) => product,
                None => {
                    let _ = device.close_function.call0(&JsValue::NULL);
                    return Err(JavascriptError::NotBootloader);
                }
            };
        Ok(Bootloader {
            device: crate::bootloader::Bootloader::from_transport(device.read_write, product),
            close_function: device.close_function,
        })
    }

    /// Closes the connection without using it.
    #[wasm_bindgen(js_name = close)]
    pub fn close(mut self) {
        if let Some(device) = self.device.take() {
            let _ = device.close_function.call0(&JsValue::NULL);
        }
    }
}

/// Connect to a BitBox02 over WebHID without assuming which mode it is in. Use
/// `Connection.isBootloader()` to branch, then `intoBitBox()` or `intoBootloader()`.
#[wasm_bindgen(js_name = bitbox02ConnectAnyWebHID)]
pub async fn bitbox02_connect_any_webhid(
    on_close_cb: TsOnCloseCb,
) -> Result<Connection, JavascriptError> {
    let result = getWebHIDDevice(
        crate::constants::VENDOR_ID as _,
        crate::constants::PRODUCT_ID as _,
        on_close_cb,
    )
    .await
    .map_err(|_| JavascriptError::CouldNotOpenWebHID)?;
    if result.is_null() {
        return Err(JavascriptError::UserAbort);
    }
    Ok(Connection {
        device: Some(get_js_device(&result)?),
    })
}

/// Connect to a BitBox02 using WebHID. WebHID is mainly supported by Chrome.
///
/// Fails with code `bootloader-mode` if the selected device is running its bootloader; use
/// `bitbox02ConnectAnyWebHID()` to handle both modes.
#[wasm_bindgen(js_name = bitbox02ConnectWebHID)]
pub async fn bitbox02_connect_webhid(on_close_cb: TsOnCloseCb) -> Result<BitBox, JavascriptError> {
    bitbox02_connect_any_webhid(on_close_cb)
        .await?
        .into_bitbox()
        .await
}

/// Connect to a BitBox02 by using the BitBoxBridge service.
#[wasm_bindgen(js_name = bitbox02ConnectBridge)]
pub async fn bitbox02_connect_bridge(on_close_cb: TsOnCloseCb) -> Result<BitBox, JavascriptError> {
    let result = getBridgeDevice(on_close_cb).await.map_err(|err| {
        let error_message = if err.is_instance_of::<js_sys::Error>() {
            let js_error: js_sys::Error = err.into();
            js_error.message().as_string().unwrap_or_default()
        } else {
            String::from("Unknown error")
        };
        JavascriptError::CouldNotOpenBridge(error_message)
    })?;
    if result.is_null() {
        return Err(JavascriptError::UserAbort);
    }
    let device = get_js_device(&result)?;
    let communication = Box::new(communication::U2fWsCommunication::from(
        device.read_write,
        communication::FIRMWARE_CMD,
    ));

    Ok(BitBox {
        device: crate::BitBox::from(communication, Box::new(noise::LocalStorageNoiseConfig {}))
            .await?,
        close_function: device.close_function,
    })
}

/// Connect to a BitBox02 using WebHID if available. If WebHID is not available, we attempt to
/// connect using the BitBoxBridge.
#[wasm_bindgen(js_name = bitbox02ConnectAuto)]
pub async fn bitbox02_connect_auto(on_close_cb: TsOnCloseCb) -> Result<BitBox, JavascriptError> {
    if hasWebHID() {
        bitbox02_connect_webhid(on_close_cb).await
    } else {
        bitbox02_connect_bridge(on_close_cb).await
    }
}
