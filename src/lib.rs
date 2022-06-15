use pyo3::exceptions;
use pyo3::prelude::*;
use snarkvm::dpc::{Network, Record};
use snarkvm::dpc::testnet2::Testnet2;
use snarkvm::prelude::{DecryptionKey, FromBytes, ToBytes, Transaction};

#[pymodule]
#[pyo3(name = "aleo")]
fn module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_transaction_id, m)?)?;
    m.add_function(wrap_pyfunction!(get_record, m)?)?;
    m.add_function(wrap_pyfunction!(get_record_commitment, m)?)?;
    Ok(())
}

#[pyfunction]
fn get_transaction_id(bytes: &[u8]) -> PyResult<Vec<u8>> {
    return match Transaction::<Testnet2>::read_le_unchecked(bytes) {
        Ok(transaction) => {
            match transaction.transaction_id().to_bytes_le() {
                Ok(id) => Ok(id),
                Err(_) => Err(exceptions::PyValueError::new_err("failed to convert transaction id to bytes")),
            }
        }
        Err(_) => Err(exceptions::PyValueError::new_err("failed to parse transaction")),
    };
}

#[pyfunction]
fn get_record(record_view_key: &[u8], ciphertext: &[u8]) -> PyResult<Vec<u8>> {
    return if let Ok(rvk) = <Testnet2 as Network>::RecordViewKey::from_bytes_le(record_view_key) {
        if let Ok(ciphertext) = <Testnet2 as Network>::RecordCiphertext::from_bytes_le(ciphertext) {
            match Record::<Testnet2>::decrypt(&DecryptionKey::RecordViewKey(rvk), &ciphertext) {
                Ok(record) => {
                    match record.to_bytes_le() {
                        Ok(record_bytes) => Ok(record_bytes),
                        Err(_) => Err(exceptions::PyValueError::new_err("failed to convert record to bytes")),
                    }
                }
                Err(_) => Err(exceptions::PyValueError::new_err("failed to decrypt record")),
            }
        } else {
            Err(exceptions::PyValueError::new_err("failed to parse ciphertext"))
        }
    } else {
        Err(exceptions::PyValueError::new_err("failed to parse record view key"))
    };
}

#[pyfunction]
fn get_record_commitment(record: &[u8]) -> PyResult<Vec<u8>> {
    return match Record::<Testnet2>::from_bytes_le(record) {
        Ok(record) => {
            match record.commitment().to_bytes_le() {
                Ok(commitment) => Ok(commitment),
                Err(_) => Err(exceptions::PyValueError::new_err("failed to convert record commitment to bytes")),
            }
        }
        Err(_) => Err(exceptions::PyValueError::new_err("failed to parse record")),
    };
}