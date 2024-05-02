use crate::{
    gas::{self, warm_cold_cost},
    interpreter::Interpreter,
    primitives::{Bytes, Log, LogData, Spec, SpecId::*, B256, U256},
    Host, InstructionResult, SStoreResult,
};
use core::cmp::min;
use revm_primitives::{alloy_primitives::B512, Address, BLOCKHASH_SERVE_WINDOW, BLOCKHASH_STORAGE_ADDRESS, BLOCK_HASH_HISTORY};
use std::vec::Vec;

// EIP-3074
pub fn auth<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    // Pop the `authority` off of the stack
    pop_address!(interpreter, authority);
    // Pop the signature offset and length off of the stack
    pop!(interpreter, signature_offset, signature_len);

    let signature_offset = as_usize_or_fail!(interpreter, signature_offset);
    let signature_len = as_usize_or_fail!(interpreter, signature_len);

    // Charge the fixed cost for the `AUTH` opcode
    gas!(interpreter, gas::AUTH);

    // Grab the memory region for the input data and charge for any memory expansion
    resize_memory!(interpreter, signature_offset, signature_len);
    let mem_slice = interpreter
        .shared_memory
        .slice(signature_offset, signature_len);

    // recId (yParity) is the first byte.
    let recid = mem_slice[0];
    // signature (r & s values) are the next 64 bytes.
    let signature = <&B512>::try_from(&mem_slice[1..65]).unwrap();
    let sig_len = signature.len() + 1;

    // If the memory region is longer than 65 bytes, pull the commit from the next [1, 32] bytes.
    let commit = (mem_slice.len() > sig_len).then(|| {
        let mut buf = B256::ZERO;
        let remaining = mem_slice.len() - sig_len;
        let cpy_size = (remaining > 32).then_some(32).unwrap_or(remaining);
        buf[0..remaining].copy_from_slice(&mem_slice[sig_len..sig_len + cpy_size]);
        buf
    });

    // Build the original auth message and compute the hash.
    let mut message = [0u8; 129];
    message[0] = 0x04; // AUTH_MAGIC - add constant?
    message[1..33].copy_from_slice(
        U256::from(host.env().cfg.chain_id)
            .to_be_bytes::<32>()
            .as_ref(),
    );
    message[33..65].copy_from_slice(
        U256::from(host.nonce(authority).unwrap())
            .to_be_bytes::<32>()
            .as_ref(),
    );
    message[65..97].copy_from_slice(interpreter.contract().target_address.into_word().as_ref());
    message[97..129].copy_from_slice(commit.unwrap_or_default().as_ref());
    let message_hash = revm_primitives::keccak256(&message);

    // Verify the signature
    let recovered = revm_primitives::secp256k1::ecrecover(&signature, recid, &message_hash);

    if recovered.is_err() || Address::from_word(recovered.unwrap_or_default()) != authority {
        push!(interpreter, U256::ZERO);
    } else {
        push!(interpreter, U256::from(1));
        interpreter.authorized = Some(authority);
    }
}

pub fn balance<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    pop_address!(interpreter, address);
    let Some((balance, is_cold)) = host.balance(address) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    gas!(
        interpreter,
        if SPEC::enabled(BERLIN) {
            warm_cold_cost(is_cold)
        } else if SPEC::enabled(ISTANBUL) {
            // EIP-1884: Repricing for trie-size-dependent opcodes
            700
        } else if SPEC::enabled(TANGERINE) {
            400
        } else {
            20
        }
    );
    push!(interpreter, balance);
}

/// EIP-1884: Repricing for trie-size-dependent opcodes
pub fn selfbalance<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    check!(interpreter, ISTANBUL);
    gas!(interpreter, gas::LOW);
    let Some((balance, _)) = host.balance(interpreter.contract.target_address) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    push!(interpreter, balance);
}

pub fn extcodesize<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    pop_address!(interpreter, address);
    let Some((code, is_cold)) = host.code(address) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    if SPEC::enabled(BERLIN) {
        gas!(interpreter, warm_cold_cost(is_cold));
    } else if SPEC::enabled(TANGERINE) {
        gas!(interpreter, 700);
    } else {
        gas!(interpreter, 20);
    }

    push!(interpreter, U256::from(code.len()));
}

/// EIP-1052: EXTCODEHASH opcode
pub fn extcodehash<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    check!(interpreter, CONSTANTINOPLE);
    pop_address!(interpreter, address);
    let Some((code_hash, is_cold)) = host.code_hash(address) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    if SPEC::enabled(BERLIN) {
        gas!(interpreter, warm_cold_cost(is_cold));
    } else if SPEC::enabled(ISTANBUL) {
        gas!(interpreter, 700);
    } else {
        gas!(interpreter, 400);
    }
    push_b256!(interpreter, code_hash);
}

pub fn extcodecopy<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    pop_address!(interpreter, address);
    pop!(interpreter, memory_offset, code_offset, len_u256);

    let Some((code, is_cold)) = host.code(address) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };

    let len = as_usize_or_fail!(interpreter, len_u256);
    gas_or_fail!(
        interpreter,
        gas::extcodecopy_cost(SPEC::SPEC_ID, len as u64, is_cold)
    );
    if len == 0 {
        return;
    }
    let memory_offset = as_usize_or_fail!(interpreter, memory_offset);
    let code_offset = min(as_usize_saturated!(code_offset), code.len());
    resize_memory!(interpreter, memory_offset, len);

    // Note: this can't panic because we resized memory to fit.
    interpreter
        .shared_memory
        .set_data(memory_offset, code_offset, len, &code.original_bytes());
}

pub fn blockhash<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    gas!(interpreter, gas::BLOCKHASH);
    pop_top!(interpreter, number);

    let block_number = host.env().block.number;

    match block_number.checked_sub(*number) {
        Some(diff) if !diff.is_zero() => {
            let diff = as_usize_saturated!(diff);

            // blockhash should push zero if number is same as current block number.
            if SPEC::enabled(PRAGUE) && diff <= BLOCKHASH_SERVE_WINDOW {
                let value = sload!(
                    interpreter,
                    host,
                    BLOCKHASH_STORAGE_ADDRESS,
                    number.wrapping_rem(U256::from(BLOCKHASH_SERVE_WINDOW))
                );
                *number = value;
                return;
            } else if diff <= BLOCK_HASH_HISTORY {
                let Some(hash) = host.block_hash(*number) else {
                    interpreter.instruction_result = InstructionResult::FatalExternalError;
                    return;
                };
                *number = U256::from_be_bytes(hash.0);
                return;
            }
        }
        _ => {
            // If blockhash is requested for the current block, the hash should be 0, so we fall
            // through.
        }
    }

    *number = U256::ZERO;
}

pub fn sload<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    pop_top!(interpreter, index);
    let value = sload!(
        interpreter,
        host,
        interpreter.contract.target_address,
        *index
    );
    *index = value;
}

pub fn sstore<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    require_non_staticcall!(interpreter);

    pop!(interpreter, index, value);
    let Some(SStoreResult {
        original_value: original,
        present_value: old,
        new_value: new,
        is_cold,
    }) = host.sstore(interpreter.contract.target_address, index, value)
    else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    gas_or_fail!(interpreter, {
        let remaining_gas = interpreter.gas.remaining();
        gas::sstore_cost(SPEC::SPEC_ID, original, old, new, remaining_gas, is_cold)
    });
    refund!(
        interpreter,
        gas::sstore_refund(SPEC::SPEC_ID, original, old, new)
    );
}

/// EIP-1153: Transient storage opcodes
/// Store value to transient storage
pub fn tstore<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    check!(interpreter, CANCUN);
    require_non_staticcall!(interpreter);
    gas!(interpreter, gas::WARM_STORAGE_READ_COST);

    pop!(interpreter, index, value);

    host.tstore(interpreter.contract.target_address, index, value);
}

/// EIP-1153: Transient storage opcodes
/// Load value from transient storage
pub fn tload<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    check!(interpreter, CANCUN);
    gas!(interpreter, gas::WARM_STORAGE_READ_COST);

    pop_top!(interpreter, index);

    *index = host.tload(interpreter.contract.target_address, *index);
}

pub fn log<const N: usize, H: Host + ?Sized>(interpreter: &mut Interpreter, host: &mut H) {
    require_non_staticcall!(interpreter);

    pop!(interpreter, offset, len);
    let len = as_usize_or_fail!(interpreter, len);
    gas_or_fail!(interpreter, gas::log_cost(N as u8, len as u64));
    let data = if len == 0 {
        Bytes::new()
    } else {
        let offset = as_usize_or_fail!(interpreter, offset);
        resize_memory!(interpreter, offset, len);
        Bytes::copy_from_slice(interpreter.shared_memory.slice(offset, len))
    };

    if interpreter.stack.len() < N {
        interpreter.instruction_result = InstructionResult::StackUnderflow;
        return;
    }

    let mut topics = Vec::with_capacity(N);
    for _ in 0..N {
        // SAFETY: stack bounds already checked few lines above
        topics.push(B256::from(unsafe { interpreter.stack.pop_unsafe() }));
    }

    let log = Log {
        address: interpreter.contract.target_address,
        data: LogData::new(topics, data).expect("LogData should have <=4 topics"),
    };

    host.log(log);
}

pub fn selfdestruct<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    require_non_staticcall!(interpreter);
    pop_address!(interpreter, target);

    let Some(res) = host.selfdestruct(interpreter.contract.target_address, target) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };

    // EIP-3529: Reduction in refunds
    if !SPEC::enabled(LONDON) && !res.previously_destroyed {
        refund!(interpreter, gas::SELFDESTRUCT)
    }
    gas!(interpreter, gas::selfdestruct_cost(SPEC::SPEC_ID, res));

    interpreter.instruction_result = InstructionResult::SelfDestruct;
}
