// Fixture v7 — warning-only upgrade of v6.
//
// Rules exercised by the v6→v7 pair (all Warning severity):
//   union_case_type_widened   Transfer payload: u32 → u64
//   struct_field_added        Inner gains new metadata field
//   struct_field_type_widened Ledger.balance: u32 → u64
//   error_enum_case_added     VaultError gains Frozen case
//
// No Critical findings — exits 0 without --strict, exits 1 under --strict.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env};

// ── Union: Transfer payload widened (Warning) ─────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum TransferAction {
    Cancel,
    Transfer(u64),   // WARN: widened from u32 (union_case_type_widened)
}

// ── Structs: field added + field widened (both Warning) ───────────────────────

#[contracttype]
#[derive(Clone)]
pub struct Inner {
    pub amount: u32,
    pub label: u32,
    pub metadata: u32,  // WARN: new field added (struct_field_added)
}

#[contracttype]
#[derive(Clone)]
pub struct Ledger {
    pub balance: u64,   // WARN: widened from u32 (struct_field_type_widened)
    pub owner: u32,
}

// ── Error enum: new case added (Warning) ──────────────────────────────────────

#[contracttype]
#[derive(Clone, Copy, PartialEq)]
pub enum VaultError {
    InsufficientFunds = 10,
    NotAuthorized = 20,
    Frozen = 30,        // WARN: new case (error_enum_case_added)
}

// ── Contract (unchanged interface) ───────────────────────────────────────────

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
