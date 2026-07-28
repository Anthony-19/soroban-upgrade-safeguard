// Fixture v5 — breaking upgrade of v4.
//
// Rules exercised by the v4→v5 pair:
//   union_case_removed            Cancel case removed from PaymentAction
//   union_case_reordered          Remaining cases shift discriminant positions
//   union_case_type_changed       Transfer payload: u32 → u64
//   error_enum_case_value_changed InsufficientFunds: code 10 → 99
//   error_enum_case_removed       NotAuthorized removed from VaultError
//   struct_field_type_changed     Inner.amount: u32 → bool
//   cascading_layout_break        Outer.items: Vec<Inner> — Outer inherits the break
//   cascading_layout_break        process_outer parameter: Outer inherits the break
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env, Vec};

// ── Union type (BREAK: Cancel removed; Transfer payload widened u32→u64) ─────

#[contracttype]
#[derive(Clone)]
pub enum PaymentAction {
    // BREAK: Cancel variant removed (union_case_removed)
    Transfer(u64),   // BREAK: payload changed u32 → u64 (union_case_type_changed)
}

// ── Error enum (BREAK: code change + case removal) ───────────────────────────

#[contracttype]
#[derive(Clone, Copy, PartialEq)]
pub enum VaultError {
    InsufficientFunds = 99, // BREAK: was 10 (error_enum_case_value_changed)
    // BREAK: NotAuthorized removed (error_enum_case_removed)
    LimitExceeded = 30,
}

// ── Nested / cascading types (BREAK: Inner.amount type changed) ───────────────

/// Inner struct — amount field type changed from u32 → bool.
/// This break cascades into Outer (which embeds Inner) and into every function
/// that uses Outer or Inner.
#[contracttype]
#[derive(Clone)]
pub struct Inner {
    pub amount: bool,  // BREAK: was u32 (struct_field_type_changed → cascades)
    pub label: u32,
}

/// Outer struct unchanged structurally, but Inner changed → cascading break.
#[contracttype]
#[derive(Clone)]
pub struct Outer {
    pub items: Vec<Inner>,
    pub version: u32,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct VaultContract;

#[contractimpl]
impl VaultContract {
    pub fn pay(_env: Env, _action: PaymentAction) -> u32 {
        0
    }

    pub fn process_outer(_env: Env, _data: Outer) -> u32 {
        0
    }

    pub fn process_inner(_env: Env, _inner: Inner) -> u32 {
        0
    }

    pub fn redeem(_env: Env, _amount: u32) -> VaultError {
        VaultError::InsufficientFunds
    }
}
