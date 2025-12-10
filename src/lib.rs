mod class;
mod method;

use method::*;
use pyo3::{create_exception, exceptions::PyException, prelude::*};

create_exception!(aleo_explorer_rust, RustExecuteError, PyException);

#[pymodule]
#[pyo3(name = "aleo_explorer_rust")]
fn extension(m: &Bound<PyModule>) -> PyResult<()> {
    m.add("RustExecuteError", m.py().get_type_bound::<RustExecuteError>())?;
    m.add_function(wrap_pyfunction!(sign_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(bech32_decode, m)?)?;
    m.add_function(wrap_pyfunction!(bech32_encode, m)?)?;
    m.add_function(wrap_pyfunction!(get_mapping_id, m)?)?;
    m.add_function(wrap_pyfunction!(get_key_id, m)?)?;
    m.add_function(wrap_pyfunction!(get_value_id, m)?)?;
    m.add_function(wrap_pyfunction!(compile_program, m)?)?;
    m.add_function(wrap_pyfunction!(parse_program, m)?)?;
    m.add_function(wrap_pyfunction!(hash_ops, m)?)?;
    m.add_function(wrap_pyfunction!(commit_ops, m)?)?;
    m.add_function(wrap_pyfunction!(field_ops, m)?)?;
    m.add_function(wrap_pyfunction!(group_ops, m)?)?;
    m.add_function(wrap_pyfunction!(scalar_ops, m)?)?;
    m.add_function(wrap_pyfunction!(finalize_random_seed, m)?)?;
    m.add_function(wrap_pyfunction!(chacha_random_seed, m)?)?;
    m.add_function(wrap_pyfunction!(chacha_random_value, m)?)?;
    m.add_function(wrap_pyfunction!(signature_to_address, m)?)?;
    m.add_function(wrap_pyfunction!(compute_key_to_address, m)?)?;
    m.add_function(wrap_pyfunction!(program_id_to_address, m)?)?;
    m.add_function(wrap_pyfunction!(cast, m)?)?;
    m.add_function(wrap_pyfunction!(hash_bytes_to_field, m)?)?;
    m.add_function(wrap_pyfunction!(solution_to_id, m)?)?;
    m.add_function(wrap_pyfunction!(rejected_tx_original_id, m)?)?;
    m.add_function(wrap_pyfunction!(get_puzzle_program_data, m)?)?;
    m.add_function(wrap_pyfunction!(sign_verify, m)?)?;
    m.add_function(wrap_pyfunction!(program_to_string, m)?)?;
    m.add_function(wrap_pyfunction!(deserialize_ops, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_ops, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_verify_ops, m)?)?;
    Ok(())
}
