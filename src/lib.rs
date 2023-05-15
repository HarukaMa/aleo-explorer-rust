use std::str::FromStr;

use bech32::{FromBase32, ToBase32, Variant};
use pyo3::exceptions;
use pyo3::prelude::*;
use snarkvm::prelude::traits::ToBits;
use snarkvm::prelude::{Field, FromBytes, Identifier, Network, PrivateKey, ProgramID, Signature, Testnet3, ToBytes};
use snarkvm_console_program::{Plaintext, Value};

type N = Testnet3;

#[pymodule]
#[pyo3(name = "aleo")]
fn module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sign_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(bech32_decode, m)?)?;
    m.add_function(wrap_pyfunction!(bech32_encode, m)?)?;
    m.add_function(wrap_pyfunction!(get_mapping_id, m)?)?;
    m.add_function(wrap_pyfunction!(get_key_id, m)?)?;
    m.add_function(wrap_pyfunction!(get_value_id, m)?)?;
    Ok(())
}

#[pyfunction]
fn sign_nonce(private_key: &str, nonce: &[u8]) -> PyResult<Vec<u8>> {
    let private_key = PrivateKey::<N>::from_str(private_key)
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
    bech32::encode(hrp, bytes.to_base32(), Variant::Bech32m)
        .map_err(|err| exceptions::PyValueError::new_err(format!("unable to encode bech32: {}", err.to_string())))
}

#[pyfunction]
fn bech32_decode(data: &str) -> PyResult<(String, Vec<u8>)> {
    let (hrp, data, _) = bech32::decode(data)
        .map_err(|err| exceptions::PyValueError::new_err(format!("unable to decode bech32: {}", err.to_string())))?;
    Ok((hrp, Vec::<u8>::from_base32(&data).unwrap()))
}

#[pyfunction]
fn get_mapping_id(program_id: &str, mapping_name: &str) -> PyResult<String> {
    let program_id = ProgramID::<N>::from_str(program_id)
        .map_err(|_| exceptions::PyValueError::new_err("invalid program id"))?;
    let mapping_name = Identifier::<N>::from_str(mapping_name)
        .map_err(|_| exceptions::PyValueError::new_err("invalid mapping name"))?;
    <N as Network>::hash_bhp1024(&(program_id, mapping_name).to_bits_le())
        .map(|hash| hash.to_string())
        .map_err(|_| exceptions::PyValueError::new_err("invalid mapping id"))
}

#[pyfunction]
fn get_key_id(mapping_id: &str, key: &[u8]) -> PyResult<String> {
    let mapping_id =
        Field::<N>::from_str(mapping_id).map_err(|_| exceptions::PyValueError::new_err("invalid mapping id"))?;
    let key =
        Plaintext::<N>::from_bytes_le(key).map_err(|_| exceptions::PyValueError::new_err("invalid key"))?;
    let key_hash = <N as Network>::hash_bhp1024(&key.to_bits_le())
        .map_err(|_| exceptions::PyValueError::new_err("invalid key"))?;
    <N as Network>::hash_bhp1024(&(mapping_id, key_hash).to_bits_le())
        .map(|hash| hash.to_string())
        .map_err(|_| exceptions::PyValueError::new_err("invalid key id"))
}

#[pyfunction]
fn get_value_id(key_id: &str, value: &[u8]) -> PyResult<String> {
    let key_id =
        Field::<N>::from_str(key_id).map_err(|_| exceptions::PyValueError::new_err("invalid key id"))?;
    let value =
        Value::<N>::from_bytes_le(value).map_err(|_| exceptions::PyValueError::new_err("invalid value"))?;
    let value_hash = <N as Network>::hash_bhp1024(&value.to_bits_le())
        .map_err(|_| exceptions::PyValueError::new_err("invalid value"))?;
    <N as Network>::hash_bhp1024(&(key_id, value_hash).to_bits_le())
        .map(|hash| hash.to_string())
        .map_err(|_| exceptions::PyValueError::new_err("invalid value id"))
}
