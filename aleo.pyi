from typing import Any


def sign_nonce(private_key: str, nonce: bytes) -> bytes: ...


def bech32_encode(hrp: str, data: bytes) -> str: ...


def bech32_decode(data: str) -> tuple[str, bytes]: ...


def get_mapping_id(program_id: str, mapping_name: str) -> str: ...


def get_key_id(mapping_id: str, key: bytes) -> str: ...


def get_value_id(key_id: str, value: bytes) -> str: ...


def compile_program(program: str, program_name: str, imports: list[tuple[str, str]]) -> bytes: ...


def parse_program(program: str) -> bytes: ...


def hash_ops(input: bytes, hash_type: str, destination_type: Any) -> bytes: ...


def commit_ops(input: bytes, randomness: Any, commit_type: str, destination_type: Any) -> bytes: ...


def address_cast(input: str, destination_type: Any, lossy: bool) -> bytes: ...


def field_ops(a: Any, b: Any, op: str) -> bytes: ...


def field_cast(input: Any, destination_type: Any, lossy: bool) -> bytes: ...


def group_ops(a: Any, b: Any, op: str) -> bytes: ...


def group_cast(input: Any, destination_type: Any, lossy: bool) -> bytes: ...


def scalar_ops(a: Any, b: Any, op: str) -> bytes: ...


def scalar_cast(input: Any, destination_type: Any, lossy: bool) -> bytes: ...


def finalize_random_seed(
        block_round: int,
        block_height: int,
        block_cumulative_weight: int,
        block_cumulative_proof_target: int,
        previous_block_hash: bytes,
) -> bytes: ...


def chacha_random_seed(
        state_seed: bytes,
        transition_id: bytes,
        program_id: bytes,
        function_name: bytes,
        destination_locator: int,
        destination_type_id: int,
        additional_seeds: list[bytes],
) -> bytes: ...


def chacha_random_value(
        random_seed: bytes,
        destination_type: Any,
) -> bytes: ...

def signature_to_address(signature: str) -> str: ...