use crate::{utilities::right_pad, Error, Precompile, PrecompileResult, PrecompileWithAddress};
use revm_primitives::{alloy_primitives::B512, secp256k1, Bytes, B256};

pub const ECRECOVER: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(1),
    Precompile::Standard(ec_recover_run),
);

pub fn ec_recover_run(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const ECRECOVER_BASE: u64 = 3_000;

    if ECRECOVER_BASE > gas_limit {
        return Err(Error::OutOfGas);
    }

    let input = right_pad::<128>(input);

    // `v` must be a 32-byte big-endian integer equal to 27 or 28.
    if !(input[32..63].iter().all(|&b| b == 0) && matches!(input[63], 27 | 28)) {
        return Ok((ECRECOVER_BASE, Bytes::new()));
    }

    let msg = <&B256>::try_from(&input[0..32]).unwrap();
    let recid = input[63] - 27;
    let sig = <&B512>::try_from(&input[64..128]).unwrap();

    let out = secp256k1::ecrecover(sig, recid, msg)
        .map(|o| o.to_vec().into())
        .unwrap_or_default();
    Ok((ECRECOVER_BASE, out))
}
