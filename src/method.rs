use std::{collections::HashMap, ops::Neg, str::FromStr};

use bech32::{Checksum, primitives::decode::CheckedHrpstring};
use pyo3::{
    exceptions,
    prelude::*,
    types::{PyBytes, PyTuple},
};
use rand::random;
use rand_chacha::{ChaCha20Rng, ChaChaRng, rand_core::SeedableRng};
// use leo_ast::Stub;
// use leo_compiler::Compiler;
// use leo_disassembler::disassemble_from_str;
// use leo_errors::emitter::Handler;
// use leo_span::{symbol::create_session_if_not_set_then, Symbol};
use snarkvm_circuit_network::AleoTestnetV0;
use snarkvm_console_account::{ComputeKey, PrivateKey, Signature};
use snarkvm_console_network::{
    TestnetV0,
    ToBits,
    prelude::{FromBytes, Pow, ToBytes},
};
use snarkvm_console_program::{
    Address,
    ArrayType,
    Boolean,
    Double,
    Field,
    Group,
    I8,
    I16,
    I32,
    I64,
    I128,
    Identifier,
    Inverse,
    Literal,
    LiteralType,
    Locator,
    Network,
    Plaintext,
    PlaintextType,
    ProgramID,
    Scalar,
    Square,
    SquareRoot,
    StringType,
    ToFields,
    ToFieldsRaw,
    U8,
    U16,
    U32,
    U64,
    U128,
    Value,
};
use snarkvm_ledger_block::ConfirmedTransaction;
use snarkvm_ledger_puzzle::{PuzzleTrait, SolutionID};
use snarkvm_ledger_puzzle_epoch::SynthesisPuzzle;
use snarkvm_synthesizer_program::{
    DeserializeVariant,
    ECDSAVerifyVariant,
    Program,
    SerializeVariant,
    evaluate_deserialize,
    evaluate_ecdsa_verification,
    evaluate_serialize,
};
use snarkvm_utilities::{ToBits as UToBits, ToBitsRaw, Uniform};

use crate::{RustExecuteError, class::*};

type N = TestnetV0;
type A = AleoTestnetV0;

#[pyfunction]
pub fn sign_nonce(py: Python, private_key: &str, nonce: &[u8]) -> PyResult<PyObject> {
    let private_key =
        PrivateKey::<N>::from_str(private_key).map_err(|_| exceptions::PyValueError::new_err("invalid private key"))?;
    let result = Signature::sign_bytes(&private_key, nonce, &mut rand::thread_rng())
        .map(|signature| {
            signature
                .to_bytes_le()
                .map_err(|_| exceptions::PyValueError::new_err("invalid signature"))
        })
        .map_err(|_| exceptions::PyValueError::new_err("invalid signature"))??;
    Ok(PyBytes::new(py, &result).into())
}

pub enum Bech32mUnlimited {}

impl Checksum for Bech32mUnlimited {
    type MidstateRepr = u32;

    const CHECKSUM_LENGTH: usize = 6;
    const CODE_LENGTH: usize = usize::MAX;
    const GENERATOR_SH: [Self::MidstateRepr; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    const TARGET_RESIDUE: Self::MidstateRepr = 0x2bc830a3;
}

#[pyfunction]
pub fn bech32_encode(hrp: &str, bytes: &[u8]) -> PyResult<String> {
    bech32::encode::<Bech32mUnlimited>(
        bech32::Hrp::parse(hrp).map_err(|e| exceptions::PyValueError::new_err(format!("invalid hrp: {e}")))?,
        bytes,
    )
    .map_err(|err| exceptions::PyValueError::new_err(format!("unable to encode bech32: {}", err.to_string())))
}

#[pyfunction]
pub fn bech32_decode(py: Python, data: &str) -> PyResult<(String, PyObject)> {
    let p = CheckedHrpstring::new::<Bech32mUnlimited>(data)
        .map_err(|err| exceptions::PyValueError::new_err(format!("unable to decode bech32: {}", err.to_string())))?;
    Ok((
        p.hrp().to_string(),
        PyBytes::new(py, &p.byte_iter().collect::<Vec<u8>>()).into(),
    ))
}

#[pyfunction]
pub fn get_mapping_id(program_id: &str, mapping_name: &str) -> PyResult<String> {
    let program_id =
        ProgramID::<N>::from_str(program_id).map_err(|_| exceptions::PyValueError::new_err("invalid program id"))?;
    let mapping_name = Identifier::<N>::from_str(mapping_name)
        .map_err(|_| exceptions::PyValueError::new_err("invalid mapping name"))?;
    N::hash_bhp1024(&(program_id, false, mapping_name).to_bits_le())
        .map(|hash| hash.to_string())
        .map_err(|_| exceptions::PyValueError::new_err("invalid mapping id"))
}

#[pyfunction]
pub fn get_key_id(program_id: &str, mapping_name: &str, key: &[u8]) -> PyResult<String> {
    let program_id =
        ProgramID::<N>::from_str(program_id).map_err(|_| exceptions::PyValueError::new_err("invalid program id"))?;
    let mapping_name = Identifier::<N>::from_str(mapping_name)
        .map_err(|_| exceptions::PyValueError::new_err("invalid mapping name"))?;
    let key = Plaintext::<N>::from_bytes_le(key)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid key: {e}")))?;
    N::hash_bhp1024(&(program_id, false, mapping_name, false, key).to_bits_le())
        .map(|hash| hash.to_string())
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid key id: {e}")))
}

#[pyfunction]
pub fn get_value_id(key_id: &str, value: &[u8]) -> PyResult<String> {
    let key_id = Field::<N>::from_str(key_id).map_err(|_| exceptions::PyValueError::new_err("invalid key id"))?;
    let value = Value::<N>::from_bytes_le(value).map_err(|_| exceptions::PyValueError::new_err("invalid value"))?;
    let value_hash =
        N::hash_bhp1024(&value.to_bits_le()).map_err(|_| exceptions::PyValueError::new_err("invalid value"))?;
    N::hash_bhp1024(&(key_id, value_hash).to_bits_le())
        .map(|hash| hash.to_string())
        .map_err(|_| exceptions::PyValueError::new_err("invalid value id"))
}

struct TempChdir {
    old_cwd: std::path::PathBuf,
}

impl TempChdir {
    fn chdir(path: &std::path::Path) -> anyhow::Result<Self> {
        let old_cwd = std::env::current_dir()?;
        std::env::set_current_dir(path)?;
        Ok(Self { old_cwd })
    }
}

impl Drop for TempChdir {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.old_cwd).unwrap();
    }
}

#[pyfunction]
pub fn compile_program(py: Python, program: &str, program_name: &str, imports: Vec<String>) -> PyResult<PyObject> {
    Err(exceptions::PyNotImplementedError::new_err(
        "compile_program is disabled in this version",
    ))
    //     create_session_if_not_set_then(|_| {
    //         // disable output color
    //         std::env::set_var("LEO_TESTFRAMEWORK", "1");
    //
    //         let temp_dir = tempfile::tempdir()
    //             .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to create temp dir: {e}")))?;
    //
    //         let src_dir = temp_dir.path().join("src");
    //         std::fs::create_dir(src_dir.clone()).map_err(|e| {
    //             exceptions::PyRuntimeError::new_err(format!("unable to initialize directory structure: {e}"))
    //         })?;
    //
    //         let _tempcd = TempChdir::chdir(&src_dir)
    //             .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to change directory: {e}")))?;
    //
    //         std::fs::write(src_dir.join(format!("{program_name}.leo")), program).map_err(|e| {
    //             exceptions::PyRuntimeError::new_err(format!("unable to write program to temp directory: {e}"))
    //         })?;
    //
    //         let mut import_stubs: IndexMap<Symbol, Stub> = IndexMap::new();
    //
    //         for program in imports {
    //             let stub = disassemble_from_str::<N>(&program).map_err(|e| {
    //                 exceptions::PyRuntimeError::new_err(format!("unable to disassemble imported program: {e}"))
    //             })?;
    //             import_stubs.insert(Symbol::intern(&stub.stub_id.name.to_string()), stub);
    //         }
    //
    //         let build_dir = temp_dir.path().join("build");
    //
    //         let handler = Handler::default();
    //         let mut compiler = Compiler::<N>::new(
    //             program_name.to_string(),
    //             "aleo".to_string(),
    //             &handler,
    //             src_dir.join(format!("{program_name}.leo")),
    //             build_dir,
    //             None,
    //             import_stubs,
    //         );
    //         let instructions = compiler
    //             .compile()
    //             .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to compile program: {e}")))?;
    //
    //         let program = Program::<N>::from_str(&instructions)
    //             .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to parse program: {e}")))?;
    //         let result = program
    //             .to_bytes_le()
    //             .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to serialize program: {e}")))?;
    //         Ok(PyBytes::new(py, &result).into())
    //     })
}

#[pyfunction]
pub fn parse_program(py: Python, program: &str) -> PyResult<PyObject> {
    let program = Program::<N>::from_str(program)
        .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to parse program: {e}")))?;
    let result = program
        .to_bytes_le()
        .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to serialize program: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

pub fn literal_to_bytes(literal: Literal<N>) -> anyhow::Result<Vec<u8>> {
    let mut bytes = literal
        .to_bytes_le()
        .map_err(|_| anyhow::anyhow!("unable to serialize literal"))?;
    bytes.drain(0..2);
    Ok(bytes)
}

#[pyfunction]
pub fn hash_ops(py: Python, input: &[u8], type_: &str, destination_type: &[u8]) -> PyResult<PyObject> {
    let value = Value::<N>::from_bytes_le(input)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;

    let destination_type = PlaintextType::<N>::from_bytes_le(destination_type)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid destination type: {e}")))?;
    let output = if type_.starts_with("psd") {
        let value_fields = value
            .to_fields()
            .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
        let value_fields_raw = value
            .to_fields_raw()
            .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
        Plaintext::from(match destination_type {
            PlaintextType::Literal(literal_type @ LiteralType::Group)
            | PlaintextType::Literal(literal_type @ LiteralType::Address) => Literal::Group(
                match type_ {
                    "psd2" => N::hash_to_group_psd2(&value_fields),
                    "psd2_raw" => N::hash_to_group_psd2(&value_fields_raw),
                    "psd4" => N::hash_to_group_psd4(&value_fields),
                    "psd4_raw" => N::hash_to_group_psd4(&value_fields_raw),
                    "psd8" => N::hash_to_group_psd8(&value_fields),
                    "psd8_raw" => N::hash_to_group_psd8(&value_fields_raw),
                    _ => return Err(exceptions::PyValueError::new_err(format!("invalid hash type: {type_}"))),
                }
                .map_err(|e| exceptions::PyAssertionError::new_err(format!("failed to hash: {e}")))?,
            )
            .cast_lossy(literal_type)
            .map_err(|e| exceptions::PyAssertionError::new_err(format!("failed to cast: {e}")))?,

            PlaintextType::Literal(literal_type) => Literal::Field(
                match type_ {
                    "psd2" => N::hash_psd2(&value_fields),
                    "psd2_raw" => N::hash_psd2(&value_fields_raw),
                    "psd4" => N::hash_psd4(&value_fields),
                    "psd4_raw" => N::hash_psd4(&value_fields_raw),
                    "psd8" => N::hash_psd8(&value_fields),
                    "psd8_raw" => N::hash_psd8(&value_fields_raw),
                    _ => return Err(exceptions::PyValueError::new_err(format!("invalid hash type: {type_}"))),
                }
                .map_err(|e| exceptions::PyAssertionError::new_err(format!("failed to hash: {e}")))?,
            )
            .cast_lossy(literal_type)
            .map_err(|e| exceptions::PyAssertionError::new_err(format!("failed to cast: {e}")))?,

            _ => {
                return Err(exceptions::PyValueError::new_err(format!(
                    "invalid destination type: {destination_type} for hash type {type_}"
                )));
            }
        })
    } else {
        let value_bits = value.to_bits_le();
        let value_bits_raw = value.to_bits_raw_le();
        let check_multiple_of_8 = |bits: Vec<_>| -> Result<Vec<_>, PyErr> {
            if bits.len() % 8 != 0 {
                return Err(exceptions::PyValueError::new_err(format!(
                    "hash type '{type_}' expects input whose size in bits is a multiple of 8."
                )));
            }
            Ok(bits)
        };
        if type_.contains("native") {
            match destination_type {
                PlaintextType::Array(array_type) => Plaintext::from_bit_array(
                    match type_ {
                        "keccak256_native" => N::hash_keccak256(&value_bits),
                        "keccak256_native_raw" => N::hash_keccak256(&check_multiple_of_8(value_bits_raw)?),
                        "keccak384_native" => N::hash_keccak384(&value_bits),
                        "keccak384_native_raw" => N::hash_keccak384(&check_multiple_of_8(value_bits_raw)?),
                        "keccak512_native" => N::hash_keccak512(&value_bits),
                        "keccak512_native_raw" => N::hash_keccak512(&check_multiple_of_8(value_bits_raw)?),
                        "sha3_256_native" => N::hash_sha3_256(&value_bits),
                        "sha3_256_native_raw" => N::hash_sha3_256(&check_multiple_of_8(value_bits_raw)?),
                        "sha3_384_native" => N::hash_sha3_384(&value_bits),
                        "sha3_384_native_raw" => N::hash_sha3_384(&check_multiple_of_8(value_bits_raw)?),
                        "sha3_512_native" => N::hash_sha3_512(&value_bits),
                        "sha3_512_native_raw" => N::hash_sha3_512(&check_multiple_of_8(value_bits_raw)?),
                        _ => return Err(exceptions::PyTypeError::new_err(format!("invalid hash type: {type_}"))),
                    }
                    .map_err(|e| exceptions::PyAssertionError::new_err(format!("failed to hash: {e}")))?,
                    **array_type.length(),
                )
                .map_err(|e| exceptions::PyValueError::new_err(format!("failed to cast to destination type: {e}")))?,
                _ => {
                    return Err(exceptions::PyTypeError::new_err(format!(
                        "invalid destination type {destination_type} for hash type {type_}"
                    )));
                }
            }
        } else {
            match destination_type {
                PlaintextType::Literal(literal_type) => Plaintext::from(
                    Literal::Group(
                        match type_ {
                            "bhp256" => N::hash_to_group_bhp256(&value_bits),
                            "bhp256_raw" => N::hash_to_group_bhp256(&value_bits_raw),
                            "bhp512" => N::hash_to_group_bhp512(&value_bits),
                            "bhp512_raw" => N::hash_to_group_bhp512(&value_bits_raw),
                            "bhp768" => N::hash_to_group_bhp768(&value_bits),
                            "bhp768_raw" => N::hash_to_group_bhp768(&value_bits_raw),
                            "bhp1024" => N::hash_to_group_bhp1024(&value_bits),
                            "bhp1024_raw" => N::hash_to_group_bhp1024(&value_bits_raw),
                            "keccak256" => match N::hash_keccak256(&value_bits) {
                                Ok(hash) => N::hash_to_group_bhp256(&hash),
                                Err(e) => Err(e),
                            },
                            "keccak256_raw" => match N::hash_keccak256(&check_multiple_of_8(value_bits_raw)?) {
                                Ok(hash) => N::hash_to_group_bhp256(&hash),
                                Err(e) => Err(e),
                            },
                            "keccak384" => match N::hash_keccak384(&value_bits) {
                                Ok(hash) => N::hash_to_group_bhp512(&hash),
                                Err(e) => Err(e),
                            },
                            "keccak384_raw" => match N::hash_keccak384(&check_multiple_of_8(value_bits_raw)?) {
                                Ok(hash) => N::hash_to_group_bhp512(&hash),
                                Err(e) => Err(e),
                            },
                            "keccak512" => match N::hash_keccak512(&value_bits) {
                                Ok(hash) => N::hash_to_group_bhp512(&hash),
                                Err(e) => Err(e),
                            },
                            "keccak512_raw" => match N::hash_keccak512(&check_multiple_of_8(value_bits_raw)?) {
                                Ok(hash) => N::hash_to_group_bhp512(&hash),
                                Err(e) => Err(e),
                            },
                            "ped64" => N::hash_to_group_ped64(&value_bits),
                            "ped64_raw" => N::hash_to_group_ped64(&value_bits_raw),
                            "ped128" => N::hash_to_group_ped128(&value_bits),
                            "ped128_raw" => N::hash_to_group_ped128(&value_bits_raw),
                            "sha3_256" => match N::hash_sha3_256(&value_bits) {
                                Ok(hash) => N::hash_to_group_bhp256(&hash),
                                Err(e) => Err(e),
                            },
                            "sha3_256_raw" => match N::hash_sha3_256(&check_multiple_of_8(value_bits_raw)?) {
                                Ok(hash) => N::hash_to_group_bhp256(&hash),
                                Err(e) => Err(e),
                            },
                            "sha3_384" => match N::hash_sha3_384(&value_bits) {
                                Ok(hash) => N::hash_to_group_bhp512(&hash),
                                Err(e) => Err(e),
                            },
                            "sha3_384_raw" => match N::hash_sha3_384(&check_multiple_of_8(value_bits_raw)?) {
                                Ok(hash) => N::hash_to_group_bhp512(&hash),
                                Err(e) => Err(e),
                            },
                            "sha3_512" => match N::hash_sha3_512(&value_bits) {
                                Ok(hash) => N::hash_to_group_bhp512(&hash),
                                Err(e) => Err(e),
                            },
                            "sha3_512_raw" => match N::hash_sha3_512(&check_multiple_of_8(value_bits_raw)?) {
                                Ok(hash) => N::hash_to_group_bhp512(&hash),
                                Err(e) => Err(e),
                            },
                            _ => return Err(exceptions::PyValueError::new_err(format!("invalid hash type: {type_}"))),
                        }
                        .map_err(|e| exceptions::PyAssertionError::new_err(format!("failed to hash: {e}")))?,
                    )
                    .cast_lossy(literal_type)
                    .map_err(|e| {
                        exceptions::PyValueError::new_err(format!("failed to cast to destination type: {e}"))
                    })?,
                ),
                _ => {
                    return Err(exceptions::PyValueError::new_err(format!(
                        "invalid destination type {destination_type} for hash type {type_}"
                    )));
                }
            }
        }
    };
    let result = output
        .to_bytes_le()
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize output: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn commit_ops(
    py: Python,
    input: &[u8],
    randomness: ExScalar,
    type_: &str,
    destination_type: ExLiteralType,
) -> PyResult<PyObject> {
    let value = Value::<N>::from_bytes_le(input)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
    let randomness: Scalar<N> = randomness
        .try_into()
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid randomness: {e}")))?;
    let value_bits = value.to_bits_le();
    let output = match type_ {
        "bhp256" => N::commit_to_group_bhp256(&value_bits, &randomness),
        "bhp512" => N::commit_to_group_bhp512(&value_bits, &randomness),
        "bhp768" => N::commit_to_group_bhp768(&value_bits, &randomness),
        "bhp1024" => N::commit_to_group_bhp1024(&value_bits, &randomness),
        "ped64" => N::commit_to_group_ped64(&value_bits, &randomness),
        "ped128" => N::commit_to_group_ped128(&value_bits, &randomness),
        _ => return Err(exceptions::PyValueError::new_err(format!("invalid type: {type_}"))),
    }
    .map_err(|e| exceptions::PyAssertionError::new_err(format!("failed to commit: {e}")))?;
    let output = Literal::Group(output)
        .cast_lossy(
            destination_type
                .try_into()
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid destination type: {e}")))?,
        )
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to cast to destination type: {e}")))?;
    let result = literal_to_bytes(output)
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize output: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn field_ops(py: Python, a: ExField, b: ExField, op: &str) -> PyResult<PyObject> {
    let a: Field<N> = a
        .try_into()
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input a: {e}")))?;
    let b: Field<N> = b
        .try_into()
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input b: {e}")))?;
    let result = match op {
        "add" => Literal::Field(a + b),
        "sub" => Literal::Field(a - b),
        "mul" => Literal::Field(a * b),
        "div" => Literal::Field(a / b),
        "gte" => Literal::Boolean(Boolean::new(a >= b)),
        "gt" => Literal::Boolean(Boolean::new(a > b)),
        "lte" => Literal::Boolean(Boolean::new(a <= b)),
        "lt" => Literal::Boolean(Boolean::new(a < b)),
        "pow" => Literal::Field(a.pow(b)),
        "inv" => Literal::Field(
            a.inverse()
                .map_err(|e| exceptions::PyValueError::new_err(format!("failed to invert: {e}")))?,
        ),
        "neg" => Literal::Field(a.neg()),
        "double" => Literal::Field(a.double()),
        "square" => Literal::Field(a.square()),
        "sqrt" => Literal::Field(
            a.square_root()
                .map_err(|e| exceptions::PyValueError::new_err(format!("failed to sqrt: {e}")))?,
        ),
        _ => return Err(exceptions::PyValueError::new_err("invalid operation")),
    };
    let result =
        literal_to_bytes(result).map_err(|e| exceptions::PyValueError::new_err(format!("operation failed: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn group_ops(py: Python, a: ExGroup, b: PyObject, op: &str) -> PyResult<PyObject> {
    let a: Group<N> = a
        .try_into()
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input a: {e}")))?;
    let result = match op {
        "mul" => {
            let b: ExScalar = b
                .extract(py)
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input b: {e}")))?;
            let b: Scalar<N> = b
                .try_into()
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input b: {e}")))?;
            Literal::Group(a * b)
        }
        _ => {
            let b: ExGroup = b
                .extract(py)
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input b: {e}")))?;
            let b: Group<N> = b
                .try_into()
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input b: {e}")))?;
            match op {
                "add" => Literal::Group(a + b),
                "sub" => Literal::Group(a - b),
                "neg" => Literal::Group(a.neg()),
                "double" => Literal::Group(a.double()),
                _ => return Err(exceptions::PyValueError::new_err("invalid operation")),
            }
        }
    };
    let result =
        literal_to_bytes(result).map_err(|e| exceptions::PyValueError::new_err(format!("operation failed: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn scalar_ops(py: Python, a: ExScalar, b: PyObject, op: &str) -> PyResult<PyObject> {
    let a: Scalar<N> = a
        .try_into()
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input a: {e}")))?;
    let result = match op {
        "mul" => {
            let b: ExGroup = b
                .extract(py)
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input b: {e}")))?;
            let b: Group<N> = b
                .try_into()
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input b: {e}")))?;
            Literal::Group(a * b)
        }
        _ => {
            let b: ExScalar = b
                .extract(py)
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input b: {e}")))?;
            let b = b
                .try_into()
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input b: {e}")))?;
            match op {
                "add" => Literal::Scalar(a + b),
                "sub" => Literal::Scalar(a - b),
                "gte" => Literal::Boolean(Boolean::new(a >= b)),
                "gt" => Literal::Boolean(Boolean::new(a > b)),
                "lte" => Literal::Boolean(Boolean::new(a <= b)),
                "lt" => Literal::Boolean(Boolean::new(a < b)),
                _ => return Err(exceptions::PyValueError::new_err("invalid operation")),
            }
        }
    };
    let result =
        literal_to_bytes(result).map_err(|e| exceptions::PyValueError::new_err(format!("operation failed: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn finalize_random_seed(
    py: Python,
    block_round: u64,
    block_height: u32,
    block_cumulative_weight: u128,
    block_cumulative_proof_target: u128,
    previous_block_hash: &[u8],
    block_timestamp: Option<i64>,
) -> PyResult<PyObject> {
    let previous_block_hash = <N as Network>::BlockHash::from_bytes_le(previous_block_hash)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid block hash: {e}")))?;
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&block_round.to_bits_le());
    preimage.extend_from_slice(&block_height.to_bits_le());
    preimage.extend_from_slice(&block_cumulative_weight.to_bits_le());
    preimage.extend_from_slice(&block_cumulative_proof_target.to_bits_le());
    preimage.extend_from_slice(&previous_block_hash.to_bits_le());
    if let Some(block_timestamp) = block_timestamp {
        preimage.extend_from_slice(&block_timestamp.to_bits_le());
    }
    let result = N::hash_bhp768(&preimage)
        .map_err(|e| exceptions::PyValueError::new_err(format!("hash failed: {e}")))?
        .to_bytes_le()
        .map_err(|e| exceptions::PyValueError::new_err(format!("serialization failed: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn chacha_random_seed(
    py: Python,
    state_seed: &[u8],
    transition_id: &[u8],
    program_id: &[u8],
    function_name: &[u8],
    destination_locator: u64,
    destination_type_id: u8,
    additional_seeds: Vec<Vec<u8>>,
    v3_random: bool,
    nonce: Option<u64>,
) -> PyResult<PyObject> {
    let transition_id = <N as Network>::TransitionID::from_bytes_le(transition_id)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid transition id: {e}")))?;
    let program_id = ProgramID::<N>::from_bytes_le(program_id)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid program id: {e}")))?;
    let function_name = Identifier::<N>::from_bytes_le(function_name)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid function name: {e}")))?;
    let mut additional_seeds_value = Vec::with_capacity(2);
    for seed in additional_seeds {
        additional_seeds_value.push(
            Value::<N>::from_bytes_le(&seed)
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid additional seeds: {e}")))?,
        )
    }
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&state_seed.to_bits_le());
    preimage.extend_from_slice(&transition_id.to_bits_le());
    preimage.extend_from_slice(&program_id.to_bits_le());
    preimage.extend_from_slice(&function_name.to_bits_le());
    if v3_random {
        if nonce.is_none() {
            return Err(exceptions::PyValueError::new_err("nonce is required for v3 random"));
        }
        preimage.extend_from_slice(&nonce.unwrap().to_bits_le());
    }
    preimage.extend_from_slice(&destination_locator.to_bits_le());
    preimage.extend_from_slice(&destination_type_id.to_bits_le());
    for seed in additional_seeds_value {
        preimage.extend_from_slice(&seed.to_bits_le());
    }
    let result = N::hash_bhp1024(&preimage)
        .map_err(|e| exceptions::PyValueError::new_err(format!("hash failed: {e}")))?
        .to_bytes_le()
        .map_err(|e| exceptions::PyValueError::new_err(format!("serialization failed: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

// I'm not aware of any completely equivalent implementation of chacha20 rng in Python, so we
// resort to the same implementation used by snarkVM.
#[pyfunction]
pub fn chacha_random_value(py: Python, random_seed: &[u8], destination_type: ExLiteralType) -> PyResult<PyObject> {
    let mut rng = ChaCha20Rng::from_seed(<[u8; 32]>::try_from(random_seed)?);
    let literal_type = destination_type
        .try_into()
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid destination type: {e}")))?;
    let output = match literal_type {
        LiteralType::Address => Literal::Address(Address::new(Group::rand(&mut rng))),
        LiteralType::Boolean => Literal::Boolean(Boolean::rand(&mut rng)),
        LiteralType::Field => Literal::Field(Field::rand(&mut rng)),
        LiteralType::Group => Literal::Group(Group::rand(&mut rng)),
        LiteralType::I8 => Literal::I8(I8::rand(&mut rng)),
        LiteralType::I16 => Literal::I16(I16::rand(&mut rng)),
        LiteralType::I32 => Literal::I32(I32::rand(&mut rng)),
        LiteralType::I64 => Literal::I64(I64::rand(&mut rng)),
        LiteralType::I128 => Literal::I128(I128::rand(&mut rng)),
        LiteralType::U8 => Literal::U8(U8::rand(&mut rng)),
        LiteralType::U16 => Literal::U16(U16::rand(&mut rng)),
        LiteralType::U32 => Literal::U32(U32::rand(&mut rng)),
        LiteralType::U64 => Literal::U64(U64::rand(&mut rng)),
        LiteralType::U128 => Literal::U128(U128::rand(&mut rng)),
        LiteralType::Scalar => Literal::Scalar(Scalar::rand(&mut rng)),
        LiteralType::Signature => return Err(exceptions::PyValueError::new_err("invalid destination type")),
        LiteralType::String => return Err(exceptions::PyValueError::new_err("invalid destination type")),
    };
    let result = literal_to_bytes(output)
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize output: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn signature_to_address(signature: &str) -> PyResult<String> {
    let signature =
        Signature::<N>::from_str(signature).map_err(|_| exceptions::PyValueError::new_err("invalid signature"))?;
    Ok(signature.to_address().to_string())
}

#[pyfunction]
pub fn compute_key_to_address(compute_key: &[u8]) -> PyResult<String> {
    let compute_key = ComputeKey::<N>::from_bytes_le(compute_key)
        .map_err(|_| exceptions::PyValueError::new_err("invalid compute key"))?;
    Ok(compute_key.to_address().to_string())
}

#[pyfunction]
pub fn program_id_to_address(program_id: &str) -> PyResult<String> {
    let program_id =
        ProgramID::<N>::from_str(program_id).map_err(|_| exceptions::PyValueError::new_err("invalid program id"))?;
    Ok(program_id
        .to_address()
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to convert to address: {e}")))?
        .to_string())
}

#[pyfunction]
pub fn cast(
    py: Python,
    input: &str,
    input_type: ExLiteralType,
    destination_type: ExLiteralType,
    lossy: bool,
) -> PyResult<PyObject> {
    let cast_function = match lossy {
        true => Literal::<N>::cast_lossy,
        false => Literal::<N>::cast,
    };
    let literal_type = input_type
        .try_into()
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input type: {e}")))?;
    let literal = match literal_type {
        LiteralType::Address => Address::<N>::from_str(input).map(Literal::Address),
        LiteralType::Boolean => Boolean::from_str(input).map(Literal::Boolean),
        LiteralType::Field => Field::<N>::from_str(input).map(Literal::Field),
        LiteralType::Group => Group::<N>::from_str(input).map(Literal::Group),
        LiteralType::I8 => I8::from_str(input).map(Literal::I8),
        LiteralType::I16 => I16::from_str(input).map(Literal::I16),
        LiteralType::I32 => I32::from_str(input).map(Literal::I32),
        LiteralType::I64 => I64::from_str(input).map(Literal::I64),
        LiteralType::I128 => I128::from_str(input).map(Literal::I128),
        LiteralType::U8 => U8::from_str(input).map(Literal::U8),
        LiteralType::U16 => U16::from_str(input).map(Literal::U16),
        LiteralType::U32 => U32::from_str(input).map(Literal::U32),
        LiteralType::U64 => U64::from_str(input).map(Literal::U64),
        LiteralType::U128 => U128::from_str(input).map(Literal::U128),
        LiteralType::Scalar => Scalar::<N>::from_str(input).map(Literal::Scalar),
        LiteralType::Signature => {
            Signature::<N>::from_str(input).map(|signature| Literal::Signature(Box::from(signature)))
        }
        LiteralType::String => StringType::from_str(input).map(Literal::String),
    }
    .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
    let result = cast_function(
        &literal,
        destination_type
            .try_into()
            .map_err(|e| exceptions::PyValueError::new_err(format!("invalid destination type: {e}")))?,
    )
    .map_err(|e| RustExecuteError::new_err(format!("{e}")))?;
    let result = literal_to_bytes(result)
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize output: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn hash_bytes_to_field(py: Python, input: &[u8], type_: &str) -> PyResult<PyObject> {
    let input = &input.to_bits_le();
    let output = match type_ {
        "bhp256" => N::hash_bhp256(input),
        "bhp512" => N::hash_bhp512(input),
        "bhp768" => N::hash_bhp768(input),
        "bhp1024" => N::hash_bhp1024(input),
        "ped64" => N::hash_ped64(input),
        "ped128" => N::hash_ped128(input),
        _ => return Err(exceptions::PyValueError::new_err("invalid hash type")),
    }
    .map_err(|e| exceptions::PyValueError::new_err(format!("failed to hash: {e}")))?;
    let result = output
        .to_bytes_le()
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize output: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn solution_to_id(py: Python, epoch_hash: &str, address: &str, counter: u64) -> PyResult<PyObject> {
    let epoch_hash = <N as Network>::BlockHash::from_str(epoch_hash)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid epoch hash: {e}")))?;
    let address = Address::<N>::from_str(address)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid address: {e}")))?;
    let solution_id = SolutionID::<N>::new(epoch_hash, address, counter)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid solution id: {e}")))?;
    Ok(PyBytes::new(
        py,
        &solution_id
            .to_bytes_le()
            .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize solution id: {e}")))?,
    )
    .into())
}

#[pyfunction]
pub fn rejected_tx_original_id(confirmed_transaction: &[u8]) -> PyResult<String> {
    let confirmed_transaction = ConfirmedTransaction::<N>::from_bytes_le(confirmed_transaction)
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to parse confirmed transaction: {e}")))?;
    Ok(confirmed_transaction
        .to_unconfirmed_transaction_id()
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to get rejected tx original id: {e}")))?
        .to_string())
}

#[pyfunction]
pub fn get_puzzle_program_data(py: Python, epoch_hash: &[u8]) -> PyResult<PyObject> {
    let epoch_hash = <N as Network>::BlockHash::from_bytes_le(epoch_hash)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid epoch hash: {e}")))?;
    let puzzle = SynthesisPuzzle::<N, A>::new();
    let puzzle_program = puzzle
        .get_epoch_program(epoch_hash)
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to get puzzle program data: {e}")))?;
    let inputs = puzzle_program
        .construct_inputs(&mut ChaChaRng::seed_from_u64(random()))
        .map_err(|e| {
            exceptions::PyValueError::new_err(format!("failed to construct inputs for puzzle program data: {e}"))
        })?;
    let r1cs = puzzle_program.to_r1cs::<A>(inputs).map_err(|e| {
        exceptions::PyValueError::new_err(format!("failed to convert puzzle program data to r1cs: {e}"))
    })?;
    let program = (*puzzle_program)
        .to_bytes_le()
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize puzzle program data: {e}")))?;
    let program_bytes = PyBytes::new(py, &program).into_py(py);
    let tuple = vec![
        program_bytes,
        r1cs.num_constraints().into_py(py),
        r1cs.num_variables().into_py(py),
    ];
    Ok(PyTuple::new_bound(py, tuple).into())
}

#[pyfunction]
pub fn sign_verify(signature: &[u8], address: &[u8], message: &[u8]) -> PyResult<bool> {
    let signature = Signature::<N>::from_bytes_le(signature)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid signature: {e}")))?;
    let address = Address::<N>::from_bytes_le(address)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid address: {e}")))?;
    let message = Value::<N>::from_bytes_le(message)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid message: {e}")))?;

    let message_fields = message
        .to_fields()
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to convert message to fields: {e}")))?;
    let is_valid = signature.verify(&address, &message_fields);
    Ok(is_valid)
}

#[pyfunction]
pub fn program_to_string(program: &[u8]) -> PyResult<String> {
    let program = Program::<N>::from_bytes_le(program)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid program: {e}")))?;
    Ok(program.to_string())
}

#[pyfunction]
pub fn deserialize_ops(
    py: Python,
    variant: u8,
    input: &[u8],
    destination_type: &[u8],
    program: &[u8],
    imported_programs: Vec<Vec<u8>>,
) -> PyResult<PyObject> {
    let input = Value::<N>::from_bytes_le(input)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
    let destination_type = PlaintextType::<N>::from_bytes_le(destination_type)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid destination type: {e}")))?;
    let program = Program::<N>::from_bytes_le(program)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid program: {e}")))?;

    let mut imports: HashMap<ProgramID<N>, Program<N>> = HashMap::new();
    for imported in imported_programs {
        let imported = Program::<N>::from_bytes_le(&imported)
            .map_err(|e| exceptions::PyValueError::new_err(format!("invalid imported program: {e}")))?;
        imports.insert(*imported.id(), imported);
    }

    let get_struct = |identifier: &Identifier<N>| program.get_struct(identifier).cloned();

    let get_external_struct = |locator: &Locator<N>| -> anyhow::Result<_> {
        let ext_program = imports
            .get(locator.program_id())
            .ok_or_else(|| anyhow::anyhow!("imported program '{}' not found", locator.program_id()))?;
        ext_program.get_struct(locator.resource()).cloned()
    };

    let bits = match input {
        Value::Plaintext(plaintext) => plaintext
            .as_bit_array()
            .map_err(|e| exceptions::PyValueError::new_err(format!("failed to convert input to bits: {e}")))?,
        _ => {
            return Err(exceptions::PyValueError::new_err(
                "expected input to be a plaintext bit array",
            ));
        }
    };

    let output = evaluate_deserialize(
        DeserializeVariant::from_u8(variant),
        &bits,
        &destination_type,
        &get_struct,
        &get_external_struct,
    )
    .map_err(|e| RustExecuteError::new_err(format!("failed to evaluate deserialize: {e}")))?;
    let result = output
        .to_bytes_le()
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize output: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn serialize_ops(py: Python, variant: u8, input: &[u8], destination_type: &[u8]) -> PyResult<PyObject> {
    let input = Value::<N>::from_bytes_le(input)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
    let destination_type = ArrayType::<N>::from_bytes_le(destination_type)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid destination type: {e}")))?;
    let output = evaluate_serialize(
        match variant {
            0 => SerializeVariant::ToBits,
            1 => SerializeVariant::ToBitsRaw,
            variant => return Err(exceptions::PyValueError::new_err(format!("invalid variant: {variant}"))),
        },
        &input,
        &destination_type,
    )
    .map_err(|e| exceptions::PyValueError::new_err(format!("failed to evaluate serialize: {e}")))?;
    let result = output
        .to_bytes_le()
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize output: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn ecdsa_verify_ops(variant: u8, signature: &[u8], public_key: &[u8], message: &[u8]) -> PyResult<bool> {
    let signature = Value::<N>::from_bytes_le(signature)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid signature: {e}")))?;
    let public_key = Value::<N>::from_bytes_le(public_key)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid public key: {e}")))?;
    let message = Value::<N>::from_bytes_le(message)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid message: {e}")))?;
    evaluate_ecdsa_verification(ECDSAVerifyVariant::new(variant), &signature, &public_key, &message)
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to evaluate ecdsa verify: {e}")))
}
