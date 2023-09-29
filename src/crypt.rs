use std::io::{Read, Write};
use tink_core::keyset::{Handle};
use crate::error::GaiaError;

pub fn encrypt(mut input: impl Read + 'static, output: impl Write + 'static) -> Result<Handle, GaiaError> {
    tink_streaming_aead::init();

    let kh = Handle::new(&tink_streaming_aead::aes256_gcm_hkdf_4kb_key_template())
        .map_err(|e| GaiaError::GeneratingKey(e))?;

    let streaming_aead = tink_streaming_aead::new(&kh).map_err(|e| GaiaError::BuildingEncryption(e))?;

    let mut writer = streaming_aead.new_encrypting_writer(Box::new(output), &[])
        .map_err(|e| GaiaError::BuildingEncryption(e))?;

    std::io::copy(&mut input, &mut writer).map_err(|e| GaiaError::WritingOutput(e))?;
    Ok(kh)
}

pub fn decrypt<'a>(input: impl Read + 'static, kh: &Handle, mut output: impl Write + 'static) -> Result<(), GaiaError> {
    tink_streaming_aead::init();

    let streaming_aead = tink_streaming_aead::new(&kh).map_err(|e| GaiaError::BuildingEncryption(e))?;

    let mut reader = streaming_aead.new_decrypting_reader(Box::new(input), &[])
        .map_err(|e| GaiaError::BuildingEncryption(e))?;

    std::io::copy(&mut reader, &mut output).map_err(|e| GaiaError::WritingOutput(e))?;
    Ok(())
}