def sign_nonce(private_key: str, nonce: bytes) -> bytes: ...


def bech32_encode(hrp: str, data: bytes) -> str: ...


def bech32_decode(data: str) -> tuple[str, bytes]: ...


def get_mapping_id(program_id: str, mapping_name: str) -> str: ...


def get_key_id(mapping_id: str, key: bytes) -> str: ...


def get_value_id(key_id: str, value: bytes) -> str: ...


def compile_program(program: str, program_name: str, imports: list[tuple[str, str]]) -> bytes: ...


def parse_program(program: str) -> bytes: ...


def hash_ops(input: bytes, hash_type: str, destination_type: bytes) -> bytes: ...


def field_ops(a: bytes, b: bytes, op: str) -> bytes: ...


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
        destination_type: bytes,
) -> bytes: ...
