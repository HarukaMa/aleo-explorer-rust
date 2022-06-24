use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use snarkvm::dpc::testnet2::Testnet2;
use snarkvm::dpc::{Network, Record};
use snarkvm::prelude::{DecryptionKey, FromBytes, ToBytes, Transaction};
use snarkvm_algorithms::crh::BHPCRH;
use snarkvm_algorithms::merkle_tree::{MerkleTree, MerkleTreeParameters};
use snarkvm_algorithms::MerkleParameters;
use snarkvm_curves::edwards_bls12::EdwardsProjective;
use std::sync::Arc;

#[pymodule]
#[pyo3(name = "aleo")]
fn module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_transaction_id, m)?)?;
    m.add_function(wrap_pyfunction!(get_record, m)?)?;
    m.add_function(wrap_pyfunction!(get_record_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(get_record_ciphertext_commitment, m)?)?;
    m.add_class::<LedgerTree>()?;
    Ok(())
}

#[pyfunction]
fn get_transaction_id(bytes: &[u8]) -> PyResult<Vec<u8>> {
    return match Transaction::<Testnet2>::read_le_unchecked(bytes) {
        Ok(transaction) => match transaction.transaction_id().to_bytes_le() {
            Ok(id) => Ok(id),
            Err(_) => Err(exceptions::PyValueError::new_err(
                "failed to convert transaction id to bytes",
            )),
        },
        Err(_) => Err(exceptions::PyValueError::new_err(
            "failed to parse transaction",
        )),
    };
}

#[pyfunction]
fn get_record(record_view_key: &[u8], ciphertext: &[u8]) -> PyResult<Vec<u8>> {
    return if let Ok(rvk) = <Testnet2 as Network>::RecordViewKey::from_bytes_le(record_view_key) {
        if let Ok(ciphertext) = <Testnet2 as Network>::RecordCiphertext::from_bytes_le(ciphertext) {
            match Record::<Testnet2>::decrypt(&DecryptionKey::RecordViewKey(rvk), &ciphertext) {
                Ok(record) => match record.to_bytes_le() {
                    Ok(record_bytes) => Ok(record_bytes),
                    Err(_) => Err(exceptions::PyValueError::new_err(
                        "failed to convert record to bytes",
                    )),
                },
                Err(_) => Err(exceptions::PyValueError::new_err(
                    "failed to decrypt record",
                )),
            }
        } else {
            Err(exceptions::PyValueError::new_err(
                "failed to parse ciphertext",
            ))
        }
    } else {
        Err(exceptions::PyValueError::new_err(
            "failed to parse record view key",
        ))
    };
}

#[pyfunction]
fn get_record_commitment(record: &[u8]) -> PyResult<Vec<u8>> {
    return match Record::<Testnet2>::from_bytes_le(record) {
        Ok(record) => match record.commitment().to_bytes_le() {
            Ok(commitment) => Ok(commitment),
            Err(_) => Err(exceptions::PyValueError::new_err(
                "failed to convert record commitment to bytes",
            )),
        },
        Err(_) => Err(exceptions::PyValueError::new_err("failed to parse record")),
    };
}

#[pyfunction]
fn get_record_ciphertext_commitment(record_ciphertext: &[u8]) -> PyResult<Vec<u8>> {
    return match <Testnet2 as Network>::RecordCiphertext::from_bytes_le(record_ciphertext) {
        Ok(record_ciphertext) => match record_ciphertext.commitment().to_bytes_le() {
            Ok(commitment) => Ok(commitment),
            Err(_) => Err(exceptions::PyValueError::new_err(
                "failed to convert record commitment to bytes",
            )),
        },
        Err(_) => Err(exceptions::PyValueError::new_err(
            "failed to parse record ciphertext",
        )),
    };
}

///
/// Ledger tree for Python code
///
/// This is usable but not actually used by the explorer, mostly due to unconfirmed blocks.
/// The performance is not too good as well.
///
#[pyclass]
struct LedgerTree {
    tree: MerkleTree<MerkleTreeParameters<BHPCRH<EdwardsProjective, 16, 32>, 32>>,
    next_height: usize,
}

type BlockHash = <Testnet2 as Network>::BlockHash;

#[pymethods]
impl LedgerTree {
    #[new]
    fn new() -> PyResult<Self> {
        let tree = MerkleTree::new::<BlockHash>(
            Arc::new(MerkleTreeParameters::setup("AleoLedgerRootCRH0")),
            &[],
        );
        match tree {
            Ok(tree) => Ok(Self {
                tree,
                next_height: 0,
            }),
            Err(_) => Err(exceptions::PyValueError::new_err(
                "failed to init ledger tree",
            )),
        }
    }

    fn root(&self, py: Python) -> PyObject {
        PyBytes::new(py, &*(&self.tree.root()).to_bytes_le().unwrap()).into()
    }

    fn add_batch(&mut self, leaves: Vec<&[u8]>) {
        self.tree = match self.tree.rebuild(
            self.next_height,
            &leaves
                .iter()
                .map(|x| match BlockHash::from_bytes_le(x) {
                    Ok(b) => b,
                    Err(_) => panic!("failed to read block hash"),
                })
                .collect::<Vec<BlockHash>>(),
        ) {
            Ok(tree) => tree,
            Err(_) => panic!("failed to init ledger tree"),
        };
        self.next_height += leaves.len();
    }

    fn add(&mut self, block_hash: &[u8]) {
        self.tree = match self.tree.rebuild(
            self.next_height,
            &[match BlockHash::from_bytes_le(block_hash) {
                Ok(b) => b,
                Err(_) => panic!("failed to read block hash"),
            }],
        ) {
            Ok(tree) => tree,
            Err(_) => panic!("failed to add block"),
        };
        self.next_height += 1;
    }

    fn revert(&mut self, target_height: usize) {
        self.tree = match self.tree.rebuild::<BlockHash>(target_height + 1, &[]) {
            Ok(tree) => tree,
            Err(_) => panic!("failed to revert to height {}", target_height),
        };
        self.next_height = self.next_height.min(target_height + 1);
    }

    fn __len__(&self) -> usize {
        self.next_height
    }
}
