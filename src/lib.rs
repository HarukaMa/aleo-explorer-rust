use std::str::FromStr;

use bech32::{FromBase32, ToBase32, Variant};
use leo_compiler::Compiler;
use leo_errors::emitter::Handler;
use leo_span::symbol::create_session_if_not_set_then;
use pyo3::exceptions;
use pyo3::prelude::*;
use snarkvm_circuit_environment::{Eject, Inject, Mode, ToBits as AToBits};
use snarkvm_circuit_network::{Aleo, AleoV0};
use snarkvm_circuit_program::{Literal as ALiteral, Value as AValue};
use snarkvm_console_account::{PrivateKey, Signature};
use snarkvm_console_network::prelude::{FromBytes, ToBytes};
use snarkvm_console_network::{Testnet3, ToBits};
use snarkvm_console_program::{Field, Identifier, Literal, LiteralType, Network, Plaintext, ProgramID, Value};
use snarkvm_synthesizer::Program;

type N = Testnet3;
type A = AleoV0;

#[pymodule]
#[pyo3(name = "aleo")]
fn module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sign_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(bech32_decode, m)?)?;
    m.add_function(wrap_pyfunction!(bech32_encode, m)?)?;
    m.add_function(wrap_pyfunction!(get_mapping_id, m)?)?;
    m.add_function(wrap_pyfunction!(get_key_id, m)?)?;
    m.add_function(wrap_pyfunction!(get_value_id, m)?)?;
    m.add_function(wrap_pyfunction!(compile_program, m)?)?;
    m.add_function(wrap_pyfunction!(get_program_from_str, m)?)?;
    m.add_function(wrap_pyfunction!(hash_ops, m)?)?;
    m.add_function(wrap_pyfunction!(field_ops, m)?)?;
    Ok(())
}

#[pyfunction]
fn sign_nonce(private_key: &str, nonce: &[u8]) -> PyResult<Vec<u8>> {
    let private_key =
        PrivateKey::<N>::from_str(private_key).map_err(|_| exceptions::PyValueError::new_err("invalid private key"))?;
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
    let program_id =
        ProgramID::<N>::from_str(program_id).map_err(|_| exceptions::PyValueError::new_err("invalid program id"))?;
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
    let key = Plaintext::<N>::from_bytes_le(key)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid key: {e}")))?;
    let key_hash = <N as Network>::hash_bhp1024(&key.to_bits_le())
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid key: {e}")))?;
    <N as Network>::hash_bhp1024(&(mapping_id, key_hash).to_bits_le())
        .map(|hash| hash.to_string())
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid key id: {e}")))
}

#[pyfunction]
fn get_value_id(key_id: &str, value: &[u8]) -> PyResult<String> {
    let key_id = Field::<N>::from_str(key_id).map_err(|_| exceptions::PyValueError::new_err("invalid key id"))?;
    let value = Value::<N>::from_bytes_le(value).map_err(|_| exceptions::PyValueError::new_err("invalid value"))?;
    let value_hash = <N as Network>::hash_bhp1024(&value.to_bits_le())
        .map_err(|_| exceptions::PyValueError::new_err("invalid value"))?;
    <N as Network>::hash_bhp1024(&(key_id, value_hash).to_bits_le())
        .map(|hash| hash.to_string())
        .map_err(|_| exceptions::PyValueError::new_err("invalid value id"))
}

#[pyfunction]
fn compile_program(program: &str, program_name: &str) -> PyResult<Vec<u8>> {
    create_session_if_not_set_then(|_| {
        // disable output color
        std::env::set_var("LEO_TESTFRAMEWORK", "1");

        let temp_dir = tempfile::tempdir()
            .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to create temp dir: {e}")))?;

        let src_dir = temp_dir.path().join("src");
        std::fs::create_dir(src_dir.clone()).map_err(|e| {
            exceptions::PyRuntimeError::new_err(format!("unable to initialize directory structure: {e}"))
        })?;
        std::fs::write(src_dir.join(format!("{program_name}.leo")), program).map_err(|e| {
            exceptions::PyRuntimeError::new_err(format!("unable to write program to temp directory: {e}"))
        })?;

        let build_dir = temp_dir.path().join("build");

        let handler = Handler::default();
        let mut compiler = Compiler::new(
            program_name.to_string(),
            "aleo".to_string(),
            &handler,
            src_dir.join(format!("{program_name}.leo")),
            build_dir,
            None,
        );
        let (_, instructions) = compiler
            .compile()
            .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to compile program: {e}")))?;

        let program = Program::<N>::from_str(&instructions)
            .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to parse program: {e}")))?;
        program
            .to_bytes_le()
            .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to serialize program: {e}")))
    })
}

#[pyfunction]
fn get_program_from_str(program: &str) -> PyResult<Vec<u8>> {
    let program = Program::<N>::from_str(program)
        .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to parse program: {e}")))?;
    program
        .to_bytes_le()
        .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to serialize program: {e}")))
}

#[pyfunction]
fn hash_ops(input: &[u8], type_: &str, destination_type: &[u8]) -> PyResult<Vec<u8>> {
    let value = Value::<N>::from_bytes_le(input)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
    let avalue = AValue::<A>::new(Mode::Public, value.clone());
    let output = match type_ {
        "bhp256" => ALiteral::Group(<A as Aleo>::hash_to_group_bhp256(&avalue.to_bits_le())),
        "bhp512" => ALiteral::Group(<A as Aleo>::hash_to_group_bhp512(&avalue.to_bits_le())),
        "bhp768" => ALiteral::Group(<A as Aleo>::hash_to_group_bhp768(&avalue.to_bits_le())),
        "bhp1024" => ALiteral::Group(<A as Aleo>::hash_to_group_bhp1024(&avalue.to_bits_le())),
        _ => return Err(exceptions::PyNotImplementedError::new_err("")),
    };
    let output = output
        .downcast_lossy(
            LiteralType::from_bytes_le(destination_type)
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid destination type: {e}")))?,
        )
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to downcast: {e}")))?;
    match output.eject_value() {
        Literal::Address(v) => v.to_bytes_le(),
        Literal::Boolean(v) => v.to_bytes_le(),
        Literal::Field(v) => v.to_bytes_le(),
        Literal::Group(v) => v.to_bytes_le(),
        Literal::I8(v) => v.to_bytes_le(),
        Literal::I16(v) => v.to_bytes_le(),
        Literal::I32(v) => v.to_bytes_le(),
        Literal::I64(v) => v.to_bytes_le(),
        Literal::I128(v) => v.to_bytes_le(),
        Literal::U8(v) => v.to_bytes_le(),
        Literal::U16(v) => v.to_bytes_le(),
        Literal::U32(v) => v.to_bytes_le(),
        Literal::U64(v) => v.to_bytes_le(),
        Literal::U128(v) => v.to_bytes_le(),
        Literal::Scalar(v) => v.to_bytes_le(),
        Literal::String(v) => v.to_bytes_le(),
    }
    .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize output: {e}")))
}

#[pyfunction]
fn field_ops(a: &[u8], b: &[u8], op: &str) -> PyResult<Vec<u8>> {
    let a =
        Field::<N>::from_bytes_le(a).map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
    let b =
        Field::<N>::from_bytes_le(b).map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
    let result = match op {
        "add" => a + b,
        "sub" => a - b,
        "mul" => a * b,
        "div" => a / b,
        _ => return Err(exceptions::PyValueError::new_err("invalid operation")),
    };
    result
        .to_bytes_le()
        .map_err(|e| exceptions::PyValueError::new_err(format!("operation failed: {e}")))
}
