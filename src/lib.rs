use std::str::FromStr;
use bech32::{FromBase32, ToBase32, Variant};

use pyo3::exceptions;
use pyo3::prelude::*;
use snarkvm::prelude::{PrivateKey, Signature, Testnet3, ToBytes};

#[pymodule]
#[pyo3(name = "aleo")]
fn module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sign_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(bech32_decode, m)?)?;
    m.add_function(wrap_pyfunction!(bech32_encode, m)?)?;
    Ok(())
}

#[pyfunction]
fn sign_nonce(private_key: &str, nonce: &[u8]) -> PyResult<Vec<u8>> {
    let private_key = PrivateKey::<Testnet3>::from_str(private_key)
        .map_err(|_| exceptions::PyValueError::new_err("invalid private key"))?;
    Signature::sign_bytes(&private_key, nonce, &mut rand::thread_rng())
        .map(|signature| {
            signature
                .to_bytes_le()
                .map_err(|_| exceptions::PyValueError::new_err("invalid signature"))
        })
        .map_err(|_| exceptions::PyValueError::new_err("invalid signature"))?
}

#[pyfunction]
fn bech32_encode(hrp: &str, bytes: &[u8]) -> PyResult<String> {
    bech32::encode(hrp, bytes.to_base32(), Variant::Bech32m).map_err(|err| {
        exceptions::PyValueError::new_err(format!(
            "unable to encode bech32: {}",
            err.to_string()
        ))
    })
}

#[pyfunction]
fn bech32_decode(data: &str) -> PyResult<(String, Vec<u8>)> {
    let (hrp, data, _) = bech32::decode(data).map_err(|err| {
        exceptions::PyValueError::new_err(format!(
            "unable to decode bech32: {}",
            err.to_string()
        ))
    })?;
    Ok((hrp, Vec::<u8>::from_base32(&data).unwrap()))
}