// Fixture v4 — baseline for unions, error enums, nested containers, and
// cascading-dependency coverage.
//
// Change pairs exercised by v4→v5 (breaking) and v4→v4 (identity / zero FP):
//
//   Union:
//     - PaymentAction: union with void case (Cancel) and tuple case (Transfer(u32))
//       v5 changes Transfer payload from u32 → u64         (union_case_type_changed)
//       v5 removes Cancel                                  (union_case_removed)
//       v5 reorders cases                                  (union_case_reordered)
//
//   Error enum:
//     - VaultError: error enum with numeric codes
//       v5 changes InsufficientFunds code 10 → 99         (error_enum_case_value_changed)
//       v5 removes NotAuthorized                          (error_enum_case_removed)
//
//   Nested / cascading:
//     - Inner struct referenced by Outer struct and by a function parameter.
//       v5 changes Inner.amount from u32 → bool           (struct_field_type_changed on Inner)
//       Because Outer embeds Inner via a Vec<Inner> field,
//       and process_outer() accepts Outer, the break cascades:
//         cascading_layout_break on Outer
//         cascading_layout_break on process_outer parameter
//
//   Error enum used as a function return:
//     - redeem() returns Result<u64, VaultError>
//       Removing VaultError.NotAuthorized propagates into the return type.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env, Vec};

// ── Union type ────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum PaymentAction {
    Cancel,          // void case — discriminant 0
    Transfer(u32),   // tuple case — discriminant 1; payload u32
}

// ── Error enum ────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Copy, PartialEq)]
pub enum VaultError {
    InsufficientFunds = 10,
    NotAuthorized = 20,
    LimitExceeded = 30,
}

// ── Nested / cascading types ──────────────────────────────────────────────────

/// Inner struct referenced by Outer. Breaking Inner cascades into Outer and
/// into every function that accepts or returns Outer.
#[contracttype]
#[derive(Clone)]
pub struct Inner {
    pub amount: u32,   // v5 changes this to bool → cascading break
    pub label: u32,
}

/// Outer struct that embeds Inner inside a Vec. The Vec wrapper exercises
/// nested-container handling in the cascade detector.
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
    /// Exercises the PaymentAction union directly.
    pub fn pay(_env: Env, _action: PaymentAction) -> u32 {
        0
    }

    /// Exercises Outer (and transitively Inner) as a parameter.
    /// A break in Inner cascades through Outer into this function's parameter.
    pub fn process_outer(_env: Env, _data: Outer) -> u32 {
        0
    }

    /// Exercises Inner directly as a parameter (direct cascade path).
    pub fn process_inner(_env: Env, _inner: Inner) -> u32 {
        0
    }

    /// Exercises VaultError as a return type.
    /// Removing or renumbering VaultError cases is detected here too.
    pub fn redeem(_env: Env, _amount: u32) -> VaultError {
        VaultError::InsufficientFunds
    }
}
