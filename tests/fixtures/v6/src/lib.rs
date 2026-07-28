// Fixture v6 — clean baseline for warning-only type-widening / field-addition changes.
//
// v6→v7 pair exercises (all Warning severity):
//   union_case_type_widened   Transfer payload: u32 → u64
//   struct_field_added        Inner gains a new `metadata` field
//   struct_field_type_widened Ledger.balance: u32 → u64
//   error_enum_case_added     VaultError gains Frozen case
//
// The pair must pass without --strict and fail under --strict.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env};

// ── Union with tuple case ─────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum TransferAction {
    Cancel,
    Transfer(u32),   // v7 widens payload to u64
}

// ── Structs with widening candidates ─────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct Inner {
    pub amount: u32,
    pub label: u32,
    // v7 adds: pub metadata: u32
}

#[contracttype]
#[derive(Clone)]
pub struct Ledger {
    pub balance: u32,  // v7 widens to u64
    pub owner: u32,
}

// ── Error enum ────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Copy, PartialEq)]
pub enum VaultError {
    InsufficientFunds = 10,
    NotAuthorized = 20,
    // v7 adds: Frozen = 30
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct LedgerContract;

#[contractimpl]
impl LedgerContract {
    pub fn transfer(_env: Env, _action: TransferAction) -> u32 {
        0
    }

    pub fn update_inner(_env: Env, _data: Inner) -> u32 {
        0
    }

    pub fn update_ledger(_env: Env, _ledger: Ledger) -> u32 {
        0
    }

    pub fn check_vault(_env: Env, _amount: u32) -> VaultError {
        VaultError::InsufficientFunds
    }
}
