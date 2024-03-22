use num_bigint::BigUint;
use pyo3::prelude::*;
use snarkvm_console_network::MainnetV0;
use snarkvm_console_program::{Field, Group, LiteralType, Scalar};
use snarkvm_utilities::FromBytes;

type N = MainnetV0;

#[derive(FromPyObject)]
pub struct ExLiteralType {
    value: u8,
}

impl TryFrom<ExLiteralType> for LiteralType {
    type Error = anyhow::Error;

    fn try_from(value: ExLiteralType) -> anyhow::Result<Self> {
        Ok(match value.value {
            0 => LiteralType::Address,
            1 => LiteralType::Boolean,
            2 => LiteralType::Field,
            3 => LiteralType::Group,
            4 => LiteralType::I8,
            5 => LiteralType::I16,
            6 => LiteralType::I32,
            7 => LiteralType::I64,
            8 => LiteralType::I128,
            9 => LiteralType::U8,
            10 => LiteralType::U16,
            11 => LiteralType::U32,
            12 => LiteralType::U64,
            13 => LiteralType::U128,
            14 => LiteralType::Scalar,
            15 => LiteralType::Signature,
            16 => LiteralType::String,
            _ => anyhow::bail!("invalid literal type"),
        })
    }
}

#[derive(FromPyObject)]
pub struct ExField {
    data: BigUint,
}

impl TryFrom<ExField> for Field<N> {
    type Error = anyhow::Error;

    fn try_from(value: ExField) -> anyhow::Result<Self> {
        let mut bytes = value.data.to_bytes_le();
        bytes.resize(32, 0);
        Field::<N>::from_bytes_le(&*bytes)
    }
}

#[derive(FromPyObject)]
pub struct ExGroup {
    data: BigUint,
}

impl TryFrom<ExGroup> for Group<N> {
    type Error = anyhow::Error;

    fn try_from(value: ExGroup) -> anyhow::Result<Self> {
        let mut bytes = value.data.to_bytes_le();
        bytes.resize(32, 0);
        Group::<N>::from_bytes_le(&*bytes)
    }
}

#[derive(FromPyObject)]
pub struct ExScalar {
    data: BigUint,
}

impl TryFrom<ExScalar> for Scalar<N> {
    type Error = anyhow::Error;

    fn try_from(value: ExScalar) -> anyhow::Result<Self> {
        let mut bytes = value.data.to_bytes_le();
        bytes.resize(32, 0);
        Scalar::<N>::from_bytes_le(&*bytes)
    }
}
