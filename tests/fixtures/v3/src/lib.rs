#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env, String};

#[contracttype]
#[derive(Clone)]
pub struct ConfigData {
    pub admin: String,
    pub threshold: u32,
}

#[contracttype]
#[derive(Clone, Copy)]
pub enum StatusEvent {
    Active = 1,
    Paused = 2,
}

#[contract]
pub struct MockContract;

#[contractimpl]
impl MockContract {
    pub fn initialize(_env: Env, _new_admin: String) -> u32 {
        100
    }

    pub fn execute_action(_env: Env, _new_config: ConfigData, _status: StatusEvent) {
        // do nothing
    }
}
