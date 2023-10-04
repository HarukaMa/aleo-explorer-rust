use std::{ops::Neg, str::FromStr};

use bech32::{FromBase32, ToBase32, Variant};
use leo_compiler::Compiler;
use leo_errors::emitter::Handler;
use leo_span::symbol::create_session_if_not_set_then;
use pyo3::{exceptions, prelude::*, types::PyBytes};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use snarkvm_console_account::{PrivateKey, Signature};
use snarkvm_console_network::{
    prelude::{FromBytes, Pow, ToBytes},
    Testnet3,
    ToBits,
};
use snarkvm_console_program::{
    Address,
    Boolean,
    Double,
    Field,
    Group,
    Identifier,
    Inverse,
    Literal,
    LiteralType,
    Network,
    Plaintext,
    ProgramID,
    Scalar,
    Square,
    SquareRoot,
    ToFields,
    Value,
    I128,
    I16,
    I32,
    I64,
    I8,
    U128,
    U16,
    U32,
    U64,
    U8,
};
use snarkvm_synthesizer_program::Program;
use snarkvm_utilities::{ToBits as UToBits, Uniform};

use crate::class::*;

type N = Testnet3;

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

#[pyfunction]
pub fn bech32_encode(hrp: &str, bytes: &[u8]) -> PyResult<String> {
    bech32::encode(hrp, bytes.to_base32(), Variant::Bech32m)
        .map_err(|err| exceptions::PyValueError::new_err(format!("unable to encode bech32: {}", err.to_string())))
}

#[pyfunction]
pub fn bech32_decode(py: Python, data: &str) -> PyResult<(String, PyObject)> {
    let (hrp, data, _) = bech32::decode(data)
        .map_err(|err| exceptions::PyValueError::new_err(format!("unable to decode bech32: {}", err.to_string())))?;
    Ok((hrp, PyBytes::new(py, &Vec::<u8>::from_base32(&data).unwrap()).into()))
}

#[pyfunction]
pub fn get_mapping_id(program_id: &str, mapping_name: &str) -> PyResult<String> {
    let program_id =
        ProgramID::<N>::from_str(program_id).map_err(|_| exceptions::PyValueError::new_err("invalid program id"))?;
    let mapping_name = Identifier::<N>::from_str(mapping_name)
        .map_err(|_| exceptions::PyValueError::new_err("invalid mapping name"))?;
    N::hash_bhp1024(&(program_id, mapping_name).to_bits_le())
        .map(|hash| hash.to_string())
        .map_err(|_| exceptions::PyValueError::new_err("invalid mapping id"))
}

#[pyfunction]
pub fn get_key_id(mapping_id: &str, key: &[u8]) -> PyResult<String> {
    let mapping_id =
        Field::<N>::from_str(mapping_id).map_err(|_| exceptions::PyValueError::new_err("invalid mapping id"))?;
    let key = Plaintext::<N>::from_bytes_le(key)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid key: {e}")))?;
    let key_hash = N::hash_bhp1024(&key.to_bits_le())
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid key: {e}")))?;
    N::hash_bhp1024(&(mapping_id, key_hash).to_bits_le())
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
pub fn compile_program(
    py: Python,
    program: &str,
    program_name: &str,
    imports: Vec<(&str, &str)>,
) -> PyResult<PyObject> {
    create_session_if_not_set_then(|_| {
        // disable output color
        std::env::set_var("LEO_TESTFRAMEWORK", "1");

        let temp_dir = tempfile::tempdir()
            .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to create temp dir: {e}")))?;

        let src_dir = temp_dir.path().join("src");
        std::fs::create_dir(src_dir.clone()).map_err(|e| {
            exceptions::PyRuntimeError::new_err(format!("unable to initialize directory structure: {e}"))
        })?;

        let import_dir = src_dir.join("imports");
        std::fs::create_dir(import_dir.clone()).map_err(|e| {
            exceptions::PyRuntimeError::new_err(format!("unable to initialize directory structure: {e}"))
        })?;

        let _tempcd = TempChdir::chdir(&src_dir)
            .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to change directory: {e}")))?;

        std::fs::write(src_dir.join(format!("{program_name}.leo")), program).map_err(|e| {
            exceptions::PyRuntimeError::new_err(format!("unable to write program to temp directory: {e}"))
        })?;

        for (name, program) in imports {
            if name == "credits" {
                std::fs::write(
                    import_dir.join(format!("{name}.leo")),
                    include_bytes!("../res/credits.leo"),
                )
                .map_err(|e| {
                    exceptions::PyRuntimeError::new_err(format!("unable to write program to temp directory: {e}"))
                })?;
            } else {
                std::fs::write(import_dir.join(format!("{name}.leo")), program).map_err(|e| {
                    exceptions::PyRuntimeError::new_err(format!("unable to write program to temp directory: {e}"))
                })?;
            }
        }

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
        let result = program
            .to_bytes_le()
            .map_err(|e| exceptions::PyRuntimeError::new_err(format!("unable to serialize program: {e}")))?;
        Ok(PyBytes::new(py, &result).into())
    })
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
pub fn hash_ops(py: Python, input: &[u8], type_: &str, destination_type: ExLiteralType) -> PyResult<PyObject> {
    let value = Value::<N>::from_bytes_le(input)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;

    let destination_type: LiteralType = destination_type
        .try_into()
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid destination type: {e}")))?;
    let output = if type_.starts_with("psd") {
        let value_field = value
            .to_fields()
            .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
        match destination_type {
            LiteralType::Group | LiteralType::Address => Literal::Group(
                match type_ {
                    "psd2" => N::hash_to_group_psd2(&value_field),
                    "psd4" => N::hash_to_group_psd4(&value_field),
                    "psd8" => N::hash_to_group_psd8(&value_field),
                    _ => return Err(exceptions::PyValueError::new_err(format!("invalid hash type: {type_}"))),
                }
                .map_err(|e| exceptions::PyAssertionError::new_err(format!("failed to hash: {e}")))?,
            ),
            _ => Literal::Field(
                match type_ {
                    "psd2" => N::hash_psd2(&value_field),
                    "psd4" => N::hash_psd4(&value_field),
                    "psd8" => N::hash_psd8(&value_field),
                    _ => return Err(exceptions::PyValueError::new_err(format!("invalid hash type: {type_}"))),
                }
                .map_err(|e| exceptions::PyAssertionError::new_err(format!("failed to hash: {e}")))?,
            ),
        }
    } else {
        let value_bits = value.to_bits_le();
        Literal::Group(
            match type_ {
                "bhp256" => N::hash_to_group_bhp256(&value_bits),
                "bhp512" => N::hash_to_group_bhp512(&value_bits),
                "bhp768" => N::hash_to_group_bhp768(&value_bits),
                "bhp1024" => N::hash_to_group_bhp1024(&value_bits),
                "ped64" => N::hash_to_group_ped64(&value_bits),
                "ped128" => N::hash_to_group_ped128(&value_bits),
                _ => return Err(exceptions::PyValueError::new_err(format!("invalid hash type: {type_}"))),
            }
            .map_err(|e| exceptions::PyAssertionError::new_err(format!("failed to hash: {e}")))?,
        )
    };
    let output = output
        .cast_lossy(destination_type)
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to cast to destination type: {e}")))?;
    let result = literal_to_bytes(output)
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
pub fn address_cast(py: Python, input: &str, destination_type: ExLiteralType, lossy: bool) -> PyResult<PyObject> {
    let input =
        Address::<N>::from_str(input).map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
    let cast_function = match lossy {
        true => Literal::<N>::cast_lossy,
        false => Literal::<N>::cast,
    };
    let literal = Literal::Address(input);
    let output = cast_function(
        &literal,
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
pub fn field_cast(py: Python, input: ExField, destination_type: ExLiteralType, lossy: bool) -> PyResult<PyObject> {
    let field = input
        .try_into()
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
    let cast_function = match lossy {
        true => Literal::<N>::cast_lossy,
        false => Literal::<N>::cast,
    };
    let literal = Literal::Field(field);
    let result = cast_function(
        &literal,
        destination_type
            .try_into()
            .map_err(|e| exceptions::PyValueError::new_err(format!("invalid destination type: {e}")))?,
    )
    .map_err(|e| exceptions::PyValueError::new_err(format!("failed to cast: {e}")))?;
    let result = literal_to_bytes(result)
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize output: {e}")))?;
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
pub fn group_cast(py: Python, input: ExGroup, destination_type: ExLiteralType, lossy: bool) -> PyResult<PyObject> {
    let group = input
        .try_into()
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
    let cast_function = match lossy {
        true => Literal::<N>::cast_lossy,
        false => Literal::<N>::cast,
    };
    let literal = Literal::Group(group);
    let result = cast_function(
        &literal,
        destination_type
            .try_into()
            .map_err(|e| exceptions::PyValueError::new_err(format!("invalid destination type: {e}")))?,
    )
    .map_err(|e| exceptions::PyValueError::new_err(format!("failed to cast: {e}")))?;
    let result = literal_to_bytes(result)
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize output: {e}")))?;
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
pub fn scalar_cast(py: Python, input: ExScalar, destination_type: ExLiteralType, lossy: bool) -> PyResult<PyObject> {
    let scalar = input
        .try_into()
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid input: {e}")))?;
    let cast_function = match lossy {
        true => Literal::<N>::cast_lossy,
        false => Literal::<N>::cast,
    };
    let literal = Literal::Scalar(scalar);
    let result = cast_function(
        &literal,
        destination_type
            .try_into()
            .map_err(|e| exceptions::PyValueError::new_err(format!("invalid destination type: {e}")))?,
    )
    .map_err(|e| exceptions::PyValueError::new_err(format!("failed to cast: {e}")))?;
    let result = literal_to_bytes(result)
        .map_err(|e| exceptions::PyValueError::new_err(format!("failed to serialize output: {e}")))?;
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
) -> PyResult<PyObject> {
    let previous_block_hash = <N as Network>::BlockHash::from_bytes_le(previous_block_hash)
        .map_err(|e| exceptions::PyValueError::new_err(format!("invalid block hash: {e}")))?;
    let mut preimage = Vec::with_capacity(605);
    preimage.extend_from_slice(&block_round.to_bits_le());
    preimage.extend_from_slice(&block_height.to_bits_le());
    preimage.extend_from_slice(&block_cumulative_weight.to_bits_le());
    preimage.extend_from_slice(&block_cumulative_proof_target.to_bits_le());
    preimage.extend_from_slice(&previous_block_hash.to_bits_le());
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
    additional_seeds: Vec<&[u8]>,
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
            Value::<N>::from_bytes_le(seed)
                .map_err(|e| exceptions::PyValueError::new_err(format!("invalid additional seeds: {e}")))?,
        )
    }
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&state_seed.to_bits_le());
    preimage.extend_from_slice(&transition_id.to_bits_le());
    preimage.extend_from_slice(&program_id.to_bits_le());
    preimage.extend_from_slice(&function_name.to_bits_le());
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
pub fn signature_to_address(py: Python, signature: &str) -> PyResult<String> {
    let signature =
        Signature::<N>::from_str(signature).map_err(|_| exceptions::PyValueError::new_err("invalid signature"))?;
    Ok(signature.to_address().to_string())
}
