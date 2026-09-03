// SPDX-License-Identifier: Apache-2.0

//! BitBox02 bootloader client.
//!
//! A BitBox02 with no firmware, or one that was told to reboot into its bootloader, enumerates as
//! a different HID product and speaks a different, much smaller protocol than the firmware: no
//! noise channel, no protobuf, eight single-byte opcodes on the same U2F-HID framing, with command
//! byte `0xC3` instead of the firmware's `0xC1`.
//!
//! This is a port of the vendor's own clients, `py/bitbox02/bitbox02/bitbox02/bootloader.py` in
//! the firmware repository and `api/bootloader/device.go` in bitbox02-api-go. Nothing here is
//! new protocol.
//!
//! The device does the security work. Its bootloader verifies the vendor signatures carried in
//! the firmware container before it will boot what was written, so a host cannot make it run
//! unsigned code by flashing it; the worst a buggy host can do is leave the device in the
//! bootloader until the next successful flash. What this module does check, before any byte
//! reaches the device, is that the file is a signed container for this device's edition.

use crate::communication::{self, ReadWrite};
use crate::Product;
use bitcoin::hashes::{sha256, Hash};
use thiserror::Error;

/// U2F-HID command byte of the bootloader. The firmware uses `0xC1`.
pub const BOOTLOADER_CMD: u8 = 0x80 + 0x40 + 0x03;

/// One firmware chunk as the bootloader writes it.
pub const CHUNK_SIZE: usize = 4096;
/// 928 kB flash minus the 64 kB bootloader.
pub const MAX_FIRMWARE_SIZE: usize = 884_736;
/// Largest number of chunks a single flash can carry.
pub const FIRMWARE_CHUNKS: usize = MAX_FIRMWARE_SIZE / CHUNK_SIZE;

const NUM_ROOT_KEYS: usize = 3;
const NUM_SIGNING_KEYS: usize = 3;
const MAGIC_LEN: usize = 4;
const VERSION_LEN: usize = 4;
const SIGNING_PUBKEYS_DATA_LEN: usize = VERSION_LEN + NUM_SIGNING_KEYS * 64 + NUM_ROOT_KEYS * 64;
const FIRMWARE_DATA_LEN: usize = VERSION_LEN + NUM_SIGNING_KEYS * 64;
/// Length of the signature block between the magic and the firmware image.
pub const SIGDATA_LEN: usize = SIGNING_PUBKEYS_DATA_LEN + FIRMWARE_DATA_LEN;

const OP_VERSIONS: u8 = b'v';
const OP_HARDWARE: u8 = b'W';
const OP_HASHES: u8 = b'h';
const OP_SET_SHOW_FIRMWARE_HASH: u8 = b'H';
const OP_ERASE: u8 = b'e';
const OP_WRITE_FIRMWARE_CHUNK: u8 = b'w';
const OP_WRITE_SIG_DATA: u8 = b's';
const OP_REBOOT: u8 = b'r';

const OP_STATUS_OK: u8 = 0;

/// HID product strings the bootloaders enumerate with, one per edition.
const PRODUCT_STRING_BITBOX02_MULTI: &str = "bb02-bootloader";
const PRODUCT_STRING_BITBOX02_BTCONLY: &str = "bb02btc-bootloader";
const PRODUCT_STRING_BITBOX02_NOVA_MULTI: &str = "BitBox02 Nova Multi bl";
const PRODUCT_STRING_BITBOX02_NOVA_BTCONLY: &str = "BitBox02 Nova BTC-only bl";

/// Which edition's bootloader is connected. Decides which firmware container it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootloaderProduct {
    BitBox02Multi,
    BitBox02BtcOnly,
    BitBox02NovaMulti,
    BitBox02NovaBtcOnly,
}

impl BootloaderProduct {
    /// Identifies a bootloader by its HID product string. `None` for firmware-mode devices and
    /// for anything that is not a BitBox02.
    pub fn from_product_string(product_string: &str) -> Option<Self> {
        match product_string {
            PRODUCT_STRING_BITBOX02_MULTI => Some(BootloaderProduct::BitBox02Multi),
            PRODUCT_STRING_BITBOX02_BTCONLY => Some(BootloaderProduct::BitBox02BtcOnly),
            PRODUCT_STRING_BITBOX02_NOVA_MULTI => Some(BootloaderProduct::BitBox02NovaMulti),
            PRODUCT_STRING_BITBOX02_NOVA_BTCONLY => Some(BootloaderProduct::BitBox02NovaBtcOnly),
            _ => None,
        }
    }

    /// The firmware-mode product this bootloader belongs to.
    pub fn firmware_product(&self) -> Product {
        match self {
            BootloaderProduct::BitBox02Multi => Product::BitBox02Multi,
            BootloaderProduct::BitBox02BtcOnly => Product::BitBox02BtcOnly,
            BootloaderProduct::BitBox02NovaMulti => Product::BitBox02NovaMulti,
            BootloaderProduct::BitBox02NovaBtcOnly => Product::BitBox02NovaBtcOnly,
        }
    }

    /// The four magic bytes a signed firmware container for this edition starts with.
    pub fn sigdata_magic(&self) -> [u8; MAGIC_LEN] {
        let magic: u32 = match self {
            BootloaderProduct::BitBox02Multi => 0x653F_362B,
            BootloaderProduct::BitBox02BtcOnly => 0x1123_3B0B,
            BootloaderProduct::BitBox02NovaMulti => 0x5B64_8CEB,
            BootloaderProduct::BitBox02NovaBtcOnly => 0x4871_4774,
        };
        magic.to_be_bytes()
    }

    /// Product id the bootloader mixes into the firmware hash since bootloader 1.2.0.
    fn product_id(&self) -> u16 {
        match self {
            BootloaderProduct::BitBox02Multi => 1,
            BootloaderProduct::BitBox02BtcOnly => 2,
            BootloaderProduct::BitBox02NovaMulti => 3,
            BootloaderProduct::BitBox02NovaBtcOnly => 4,
        }
    }

    fn from_magic(magic: &[u8]) -> Option<Self> {
        [
            BootloaderProduct::BitBox02Multi,
            BootloaderProduct::BitBox02BtcOnly,
            BootloaderProduct::BitBox02NovaMulti,
            BootloaderProduct::BitBox02NovaBtcOnly,
        ]
        .into_iter()
        .find(|product| product.sigdata_magic() == magic)
    }
}

/// True if the HID product string belongs to a BitBox02 bootloader of any edition.
pub fn is_bootloader_product_string(product_string: &str) -> bool {
    BootloaderProduct::from_product_string(product_string).is_some()
}

/// Secure chip the bootloader reports. Nova devices carry the Optiga.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureChipModel {
    Atecc,
    Optiga,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("communication error: {0}")]
    Communication(#[from] communication::Error),
    #[error("bootloader answered opcode {expected:?} with opcode {got:?}")]
    UnexpectedOpcode { expected: char, got: char },
    /// The status byte the bootloader returned, as the character it is defined as in the
    /// bootloader source (`'Z'` generic, `'N'` length, `'W'` write, `'C'` check, `'E'` erase,
    /// `'L'` not ready to load, `'I'` invalid command, `'U'`/`'K'` flash unlock/lock, `'V'`
    /// version, `'M'` macro, `'A'` abort).
    #[error("bootloader returned status {0:?}")]
    Status(char),
    #[error("bootloader response has an unexpected length")]
    UnexpectedResponse,
    #[error("signed firmware file is too small to be a firmware container")]
    FirmwareTooSmall,
    #[error("signed firmware file does not start with a known BitBox02 magic")]
    InvalidMagic,
    #[error("signed firmware is for a different BitBox02 edition than the connected bootloader")]
    WrongEdition,
    #[error("firmware image is larger than the device's flash")]
    FirmwareTooBig,
}

/// A parsed `*.signed.bin` release file: `magic || sigdata || firmware`.
pub struct SignedFirmware<'a> {
    /// Edition the container was signed for.
    pub product: BootloaderProduct,
    /// The signature block the bootloader verifies against its root keys.
    pub sigdata: &'a [u8],
    /// The raw firmware image.
    pub firmware: &'a [u8],
}

impl<'a> SignedFirmware<'a> {
    /// Splits a signed firmware file and identifies its edition from the magic bytes. Rejects
    /// files that are too small or carry an unknown magic; a container for a different edition
    /// than the connected device is rejected later, in `Bootloader::flash_signed_firmware`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < MAGIC_LEN + SIGDATA_LEN {
            return Err(Error::FirmwareTooSmall);
        }
        let (magic, rest) = bytes.split_at(MAGIC_LEN);
        let product = BootloaderProduct::from_magic(magic).ok_or(Error::InvalidMagic)?;
        let (sigdata, firmware) = rest.split_at(SIGDATA_LEN);
        if firmware.len() > MAX_FIRMWARE_SIZE {
            return Err(Error::FirmwareTooBig);
        }
        Ok(SignedFirmware {
            product,
            sigdata,
            firmware,
        })
    }

    /// The monotonic firmware version number carried in the signature block. This is the number
    /// the bootloader compares against for downgrade protection, not the semver string.
    pub fn version(&self) -> u32 {
        let bytes = &self.sigdata[SIGNING_PUBKEYS_DATA_LEN..SIGNING_PUBKEYS_DATA_LEN + VERSION_LEN];
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }
}

/// A connected BitBox02 in bootloader mode.
pub struct Bootloader {
    communication: Box<dyn ReadWrite>,
    product: BootloaderProduct,
}

impl Bootloader {
    /// Wraps a raw HID transport (64-byte reports) in the bootloader's U2F-HID framing.
    pub fn from_transport(transport: Box<dyn ReadWrite>, product: BootloaderProduct) -> Self {
        Self::from_framed(
            Box::new(communication::U2fHidCommunication::from(
                transport,
                BOOTLOADER_CMD,
            )),
            product,
        )
    }

    /// Takes a transport that already applies the bootloader's framing, so that `query()` sends
    /// bare `[opcode, payload…]` messages on it. This is the seam the tests use, and what the
    /// wasm build uses for the BitBoxBridge's websocket framing.
    pub fn from_framed(communication: Box<dyn ReadWrite>, product: BootloaderProduct) -> Self {
        Bootloader {
            communication,
            product,
        }
    }

    pub fn product(&self) -> BootloaderProduct {
        self.product
    }

    /// Sends one opcode with its payload and strips the two-byte `[opcode, status]` header from
    /// the reply, failing on any non-zero status.
    async fn query(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let opcode = msg[0];
        let mut response = self.communication.query(msg).await?;
        if response.len() < 2 {
            return Err(Error::UnexpectedResponse);
        }
        if response[0] != opcode {
            return Err(Error::UnexpectedOpcode {
                expected: opcode as char,
                got: response[0] as char,
            });
        }
        if response[1] != OP_STATUS_OK {
            return Err(Error::Status(response[1] as char));
        }
        Ok(response.split_off(2))
    }

    /// Returns `(firmware version, signing pubkeys version)`, the two monotonic counters the
    /// bootloader keeps for downgrade protection.
    pub async fn versions(&self) -> Result<(u32, u32), Error> {
        let response = self.query(&[OP_VERSIONS]).await?;
        if response.len() < 8 {
            return Err(Error::UnexpectedResponse);
        }
        let firmware_version =
            u32::from_le_bytes([response[0], response[1], response[2], response[3]]);
        let signing_pubkeys_version =
            u32::from_le_bytes([response[4], response[5], response[6], response[7]]);
        Ok((firmware_version, signing_pubkeys_version))
    }

    /// Returns which secure chip the device carries. Bootloaders before 1.1.0 do not know this
    /// opcode; they only ever shipped with the ATECC, so that is what an invalid-command status
    /// maps to.
    pub async fn hardware(&self) -> Result<SecureChipModel, Error> {
        match self.query(&[OP_HARDWARE]).await {
            Ok(response) => match response.first() {
                Some(0x00) => Ok(SecureChipModel::Atecc),
                Some(0x01) => Ok(SecureChipModel::Optiga),
                _ => Err(Error::UnexpectedResponse),
            },
            Err(Error::Status('I')) => Ok(SecureChipModel::Atecc),
            Err(err) => Err(err),
        }
    }

    /// Returns `(firmware hash, signing keydata hash)`. Either can also be shown on the device
    /// screen for the customer to compare against a published value.
    pub async fn hashes(
        &self,
        display_firmware_hash: bool,
        display_signing_keydata_hash: bool,
    ) -> Result<([u8; 32], [u8; 32]), Error> {
        let response = self
            .query(&[
                OP_HASHES,
                display_firmware_hash as u8,
                display_signing_keydata_hash as u8,
            ])
            .await?;
        if response.len() < 64 {
            return Err(Error::UnexpectedResponse);
        }
        let mut firmware_hash = [0u8; 32];
        let mut signing_keydata_hash = [0u8; 32];
        firmware_hash.copy_from_slice(&response[..32]);
        signing_keydata_hash.copy_from_slice(&response[32..64]);
        Ok((firmware_hash, signing_keydata_hash))
    }

    /// Whether the bootloader shows the firmware hash on every boot.
    pub async fn show_firmware_hash_enabled(&self) -> Result<bool, Error> {
        let response = self.query(&[OP_SET_SHOW_FIRMWARE_HASH, 0xFF]).await?;
        match response.first() {
            Some(0x00) => Ok(false),
            Some(0x01) => Ok(true),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    pub async fn set_show_firmware_hash(&self, enable: bool) -> Result<(), Error> {
        self.query(&[OP_SET_SHOW_FIRMWARE_HASH, enable as u8])
            .await?;
        Ok(())
    }

    async fn erase_chunks(&self, firmware_num_chunks: u8) -> Result<(), Error> {
        self.query(&[OP_ERASE, firmware_num_chunks]).await?;
        Ok(())
    }

    /// Erases the firmware without preparing a new one.
    pub async fn erase(&self) -> Result<(), Error> {
        self.erase_chunks(0).await
    }

    /// True if the device holds no firmware. Compares the device-reported firmware hash against
    /// the hash of an all-`0xFF` image, as the vendor clients do.
    ///
    /// Uses the hash layout of bootloader 1.2.0 and later (`product id || version || image`).
    /// Every Nova bootloader is newer than that; an older BitBox02 bootloader reports a
    /// double-SHA256 over `version || image` instead and would read as "not erased" here.
    pub async fn erased(&self) -> Result<bool, Error> {
        let (firmware_version, _) = self.versions().await?;
        let (reported_firmware_hash, _) = self.hashes(false, false).await?;
        Ok(reported_firmware_hash == self.empty_firmware_hash(firmware_version))
    }

    fn empty_firmware_hash(&self, firmware_version: u32) -> [u8; 32] {
        let mut engine = sha256::Hash::engine();
        bitcoin::hashes::HashEngine::input(&mut engine, &self.product.product_id().to_le_bytes());
        bitcoin::hashes::HashEngine::input(&mut engine, &firmware_version.to_le_bytes());
        let padding = [0xFFu8; CHUNK_SIZE];
        for _ in 0..FIRMWARE_CHUNKS {
            bitcoin::hashes::HashEngine::input(&mut engine, &padding);
        }
        sha256::Hash::from_engine(engine).to_byte_array()
    }

    async fn write_chunk(&self, chunk_num: u8, chunk: &[u8]) -> Result<(), Error> {
        let mut msg = Vec::with_capacity(2 + CHUNK_SIZE);
        msg.push(OP_WRITE_FIRMWARE_CHUNK);
        msg.push(chunk_num);
        msg.extend_from_slice(chunk);
        msg.resize(2 + CHUNK_SIZE, 0xFF);
        self.query(&msg).await?;
        Ok(())
    }

    async fn flash_unsigned_firmware(
        &self,
        firmware: &[u8],
        progress: &mut dyn FnMut(f64),
    ) -> Result<(), Error> {
        if firmware.len() > FIRMWARE_CHUNKS * CHUNK_SIZE {
            return Err(Error::FirmwareTooBig);
        }
        progress(0.0);
        let num_chunks = firmware.len().div_ceil(CHUNK_SIZE);
        // `FIRMWARE_CHUNKS` is 216, so this cannot truncate.
        self.erase_chunks(num_chunks as u8).await?;
        for (chunk_num, chunk) in firmware.chunks(CHUNK_SIZE).enumerate() {
            self.write_chunk(chunk_num as u8, chunk).await?;
            progress((chunk_num + 1) as f64 / num_chunks as f64);
        }
        Ok(())
    }

    /// Writes a signed release file to the device: erase, write the image chunk by chunk, then
    /// write the signature block. `progress` is called with a value from `0.0` to `1.0` after
    /// each chunk. Call `reboot()` afterwards to start the new firmware.
    ///
    /// Refuses a container for another edition before touching the device.
    pub async fn flash_signed_firmware(
        &self,
        signed_firmware: &[u8],
        progress: &mut dyn FnMut(f64),
    ) -> Result<(), Error> {
        let parsed = SignedFirmware::parse(signed_firmware)?;
        if parsed.product != self.product {
            return Err(Error::WrongEdition);
        }
        self.flash_unsigned_firmware(parsed.firmware, progress)
            .await?;
        let mut msg = Vec::with_capacity(1 + SIGDATA_LEN);
        msg.push(OP_WRITE_SIG_DATA);
        msg.extend_from_slice(parsed.sigdata);
        self.query(&msg).await?;
        Ok(())
    }

    /// Reboots the device. The bootloader resets the MCU without answering, so this only writes
    /// and the transport is dead afterwards; the caller should drop the connection and connect
    /// again once the device re-enumerates in firmware mode.
    pub fn reboot(&self) -> Result<(), Error> {
        self.communication.write(&[OP_REBOOT])?;
        Ok(())
    }
}

#[cfg(all(test, not(feature = "multithreaded")))]
mod tests {
    use super::*;
    use crate::util::Threading;
    use async_trait::async_trait;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// What a bootloader remembers between opcodes: an erased flash that fills up chunk by
    /// chunk, then takes a signature block, then reboots.
    #[derive(Default)]
    struct FakeFlash {
        firmware_version: u32,
        signing_pubkeys_version: u32,
        loading_ready: bool,
        expected_chunks: u8,
        chunks: Vec<Vec<u8>>,
        sigdata: Option<Vec<u8>>,
        rebooted: bool,
        /// Every raw message the fake saw, in order.
        writes: Vec<Vec<u8>>,
        /// When set, the next opcode answers with this status instead of doing anything.
        fail_next_with: Option<u8>,
        pending_response: Option<Vec<u8>>,
    }

    struct FakeBootloader {
        flash: Rc<RefCell<FakeFlash>>,
    }

    impl Threading for FakeBootloader {}

    fn ok(op: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![op, OP_STATUS_OK];
        out.extend_from_slice(payload);
        out
    }

    impl FakeFlash {
        fn handle(&mut self, msg: &[u8]) -> Vec<u8> {
            let op = msg[0];
            if let Some(status) = self.fail_next_with.take() {
                return vec![op, status];
            }
            match op {
                OP_VERSIONS => {
                    let mut payload = self.firmware_version.to_le_bytes().to_vec();
                    payload.extend_from_slice(&self.signing_pubkeys_version.to_le_bytes());
                    ok(op, &payload)
                }
                OP_HARDWARE => ok(op, &[0x01]),
                OP_HASHES => ok(op, &[0xAB; 64]),
                OP_SET_SHOW_FIRMWARE_HASH => ok(op, &[0x00]),
                OP_ERASE => {
                    self.chunks.clear();
                    self.sigdata = None;
                    self.expected_chunks = msg[1];
                    self.loading_ready = msg[1] > 0;
                    ok(op, &[])
                }
                OP_WRITE_FIRMWARE_CHUNK => {
                    if !self.loading_ready {
                        return vec![op, b'L'];
                    }
                    if msg.len() != 2 + CHUNK_SIZE {
                        return vec![op, b'N'];
                    }
                    if msg[1] as usize != self.chunks.len() || msg[1] >= self.expected_chunks {
                        return vec![op, b'N'];
                    }
                    self.chunks.push(msg[2..].to_vec());
                    ok(op, &[])
                }
                OP_WRITE_SIG_DATA => {
                    if msg.len() != 1 + SIGDATA_LEN {
                        return vec![op, b'N'];
                    }
                    self.sigdata = Some(msg[1..].to_vec());
                    ok(op, &[])
                }
                OP_REBOOT => {
                    self.rebooted = true;
                    // The real bootloader resets without answering; the client never reads.
                    Vec::new()
                }
                _ => vec![op, b'I'],
            }
        }
    }

    #[async_trait(?Send)]
    impl ReadWrite for FakeBootloader {
        fn write(&self, msg: &[u8]) -> Result<usize, communication::Error> {
            let mut flash = self.flash.borrow_mut();
            flash.writes.push(msg.to_vec());
            let response = flash.handle(msg);
            flash.pending_response = Some(response);
            Ok(msg.len())
        }

        async fn read(&self) -> Result<Vec<u8>, communication::Error> {
            self.flash
                .borrow_mut()
                .pending_response
                .take()
                .ok_or(communication::Error::Read)
        }
    }

    fn bootloader_for_test(product: BootloaderProduct) -> (Bootloader, Rc<RefCell<FakeFlash>>) {
        let flash = Rc::new(RefCell::new(FakeFlash {
            firmware_version: 7,
            signing_pubkeys_version: 2,
            ..Default::default()
        }));
        let bootloader = Bootloader::from_framed(
            Box::new(FakeBootloader {
                flash: Rc::clone(&flash),
            }),
            product,
        );
        (bootloader, flash)
    }

    /// A container with the given edition's magic, a recognisable signature block and a firmware
    /// image of `firmware_len` bytes counting up from zero.
    fn signed_firmware(product: BootloaderProduct, firmware_len: usize) -> Vec<u8> {
        let mut bytes = product.sigdata_magic().to_vec();
        let mut sigdata = vec![0x51u8; SIGDATA_LEN];
        // Firmware version 42 in the firmware-data half of the block.
        sigdata[SIGNING_PUBKEYS_DATA_LEN..SIGNING_PUBKEYS_DATA_LEN + 4]
            .copy_from_slice(&42u32.to_le_bytes());
        bytes.extend_from_slice(&sigdata);
        bytes.extend((0..firmware_len).map(|i| (i % 251) as u8));
        bytes
    }

    #[test]
    fn product_strings_identify_bootloaders_only() {
        assert_eq!(
            BootloaderProduct::from_product_string("BitBox02 Nova BTC-only bl"),
            Some(BootloaderProduct::BitBox02NovaBtcOnly)
        );
        assert_eq!(
            BootloaderProduct::from_product_string("BitBox02 Nova Multi bl"),
            Some(BootloaderProduct::BitBox02NovaMulti)
        );
        assert_eq!(
            BootloaderProduct::from_product_string("bb02-bootloader"),
            Some(BootloaderProduct::BitBox02Multi)
        );
        assert_eq!(
            BootloaderProduct::from_product_string("bb02btc-bootloader"),
            Some(BootloaderProduct::BitBox02BtcOnly)
        );
        assert!(!is_bootloader_product_string("BitBox02 Nova BTC-only"));
        assert!(!is_bootloader_product_string("BitBox02"));
        assert!(!is_bootloader_product_string("Ledger Nano"));
    }

    #[test]
    fn parses_a_signed_container() {
        let bytes = signed_firmware(BootloaderProduct::BitBox02NovaBtcOnly, 10_000);
        let parsed = SignedFirmware::parse(&bytes).unwrap();
        assert_eq!(parsed.product, BootloaderProduct::BitBox02NovaBtcOnly);
        assert_eq!(parsed.sigdata.len(), SIGDATA_LEN);
        assert_eq!(parsed.firmware.len(), 10_000);
        assert_eq!(parsed.version(), 42);
        assert_eq!(&bytes[..4], &[0x48, 0x71, 0x47, 0x74]);
    }

    #[test]
    fn rejects_unknown_magic_and_short_files() {
        let mut bytes = signed_firmware(BootloaderProduct::BitBox02NovaMulti, 100);
        bytes[0] = 0x00;
        assert!(matches!(
            SignedFirmware::parse(&bytes),
            Err(Error::InvalidMagic)
        ));
        assert!(matches!(
            SignedFirmware::parse(&bytes[..MAGIC_LEN + SIGDATA_LEN - 1]),
            Err(Error::FirmwareTooSmall)
        ));
    }

    #[tokio::test]
    async fn reads_versions_hardware_and_hashes() {
        let (bootloader, _) = bootloader_for_test(BootloaderProduct::BitBox02NovaBtcOnly);
        assert_eq!(bootloader.versions().await.unwrap(), (7, 2));
        assert_eq!(
            bootloader.hardware().await.unwrap(),
            SecureChipModel::Optiga
        );
        let (firmware_hash, keydata_hash) = bootloader.hashes(false, false).await.unwrap();
        assert_eq!(firmware_hash, [0xAB; 32]);
        assert_eq!(keydata_hash, [0xAB; 32]);
        assert!(!bootloader.show_firmware_hash_enabled().await.unwrap());
    }

    #[tokio::test]
    async fn old_bootloader_without_hardware_opcode_reads_as_atecc() {
        let (bootloader, flash) = bootloader_for_test(BootloaderProduct::BitBox02BtcOnly);
        flash.borrow_mut().fail_next_with = Some(b'I');
        assert_eq!(bootloader.hardware().await.unwrap(), SecureChipModel::Atecc);
    }

    #[tokio::test]
    async fn flashes_a_signed_firmware_in_padded_chunks_then_the_signatures() {
        let (bootloader, flash) = bootloader_for_test(BootloaderProduct::BitBox02NovaBtcOnly);
        // Two full chunks and a third partial one.
        let firmware_len = 2 * CHUNK_SIZE + 1000;
        let bytes = signed_firmware(BootloaderProduct::BitBox02NovaBtcOnly, firmware_len);
        let mut progress = Vec::new();

        bootloader
            .flash_signed_firmware(&bytes, &mut |p| progress.push(p))
            .await
            .unwrap();
        bootloader.reboot().unwrap();

        let flash = flash.borrow();
        assert_eq!(flash.expected_chunks, 3);
        assert_eq!(flash.chunks.len(), 3);
        let image = &bytes[MAGIC_LEN + SIGDATA_LEN..];
        assert_eq!(flash.chunks[0], image[..CHUNK_SIZE]);
        assert_eq!(flash.chunks[1], image[CHUNK_SIZE..2 * CHUNK_SIZE]);
        assert_eq!(&flash.chunks[2][..1000], &image[2 * CHUNK_SIZE..]);
        assert!(flash.chunks[2][1000..].iter().all(|&b| b == 0xFF));
        assert_eq!(
            flash.sigdata.as_deref(),
            Some(&bytes[MAGIC_LEN..MAGIC_LEN + SIGDATA_LEN])
        );
        assert!(flash.rebooted);
        assert_eq!(progress, vec![0.0, 1.0 / 3.0, 2.0 / 3.0, 1.0]);
        // erase, three writes, signature, reboot: nothing else on the wire.
        let opcodes: Vec<u8> = flash.writes.iter().map(|w| w[0]).collect();
        assert_eq!(
            opcodes,
            vec![
                OP_ERASE,
                OP_WRITE_FIRMWARE_CHUNK,
                OP_WRITE_FIRMWARE_CHUNK,
                OP_WRITE_FIRMWARE_CHUNK,
                OP_WRITE_SIG_DATA,
                OP_REBOOT
            ]
        );
    }

    #[tokio::test]
    async fn refuses_another_editions_firmware_before_touching_the_device() {
        let (bootloader, flash) = bootloader_for_test(BootloaderProduct::BitBox02NovaBtcOnly);
        let bytes = signed_firmware(BootloaderProduct::BitBox02NovaMulti, CHUNK_SIZE);
        let result = bootloader.flash_signed_firmware(&bytes, &mut |_| {}).await;
        assert!(matches!(result, Err(Error::WrongEdition)));
        assert!(flash.borrow().writes.is_empty());
    }

    #[tokio::test]
    async fn surfaces_the_bootloaders_status_byte() {
        let (bootloader, flash) = bootloader_for_test(BootloaderProduct::BitBox02NovaBtcOnly);
        flash.borrow_mut().fail_next_with = Some(b'E');
        let bytes = signed_firmware(BootloaderProduct::BitBox02NovaBtcOnly, CHUNK_SIZE);
        let result = bootloader.flash_signed_firmware(&bytes, &mut |_| {}).await;
        assert!(matches!(result, Err(Error::Status('E'))));
        // The erase failed, so no chunk was attempted.
        assert_eq!(flash.borrow().writes.len(), 1);
    }

    #[tokio::test]
    async fn erased_compares_against_the_empty_image_hash() {
        let (bootloader, _) = bootloader_for_test(BootloaderProduct::BitBox02NovaBtcOnly);
        // The fake reports 0xAB.. as its firmware hash, which is not the empty-image hash.
        assert!(!bootloader.erased().await.unwrap());
        // Known-answer check of the hash layout itself: product id 4, version 7, all 0xFF.
        let expected = {
            let mut data = 4u16.to_le_bytes().to_vec();
            data.extend_from_slice(&7u32.to_le_bytes());
            data.extend(std::iter::repeat_n(0xFFu8, MAX_FIRMWARE_SIZE));
            sha256::Hash::hash(&data).to_byte_array()
        };
        assert_eq!(bootloader.empty_firmware_hash(7), expected);
    }

    /// Set `BITBOX02_SIGNED_FIRMWARE` to a downloaded `*.signed.bin` to check the parser against
    /// a real release file. Ignored by default because the file is not part of the repository.
    #[test]
    #[ignore]
    fn parses_a_real_release_file() {
        let path = std::env::var("BITBOX02_SIGNED_FIRMWARE").unwrap();
        let bytes = std::fs::read(path).unwrap();
        let parsed = SignedFirmware::parse(&bytes).unwrap();
        assert!(parsed.version() > 0);
        assert!(parsed.firmware.len().is_multiple_of(4));
        eprintln!(
            "product={:?} version={} firmware_len={}",
            parsed.product,
            parsed.version(),
            parsed.firmware.len()
        );
    }
}
