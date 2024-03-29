mod class;
mod method;
use method::*;
use pyo3::prelude::*;

#[pymodule]
#[pyo3(name = "aleo_explorer_rust")]
fn module(_py: Python, m: &PyModule) -> PyResult<()> {
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
    m.add_function(wrap_pyfunction!(deserialize_g1affine, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_g1affine, m)?)?;
    m.add_function(wrap_pyfunction!(program_id_to_address, m)?)?;
    m.add_function(wrap_pyfunction!(cast, m)?)?;
    Ok(())
}
