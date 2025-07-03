// Module declarations
pub mod types;
pub mod storage;
pub mod utils;
pub mod ip_registry;
pub mod nft_management;
pub mod user_management;
pub mod marketplace;

// Re-export public types and functions
pub use types::*;
pub use ip_registry::*;
pub use nft_management::*;
pub use user_management::*;
pub use marketplace::*;

use ic_cdk::{init, post_upgrade, pre_upgrade};
use candid::Principal;

// Canister lifecycle functions
#[init]
fn init() {
    // Initialize the canister
    // Any initialization logic can go here
}

#[pre_upgrade]
fn pre_upgrade() {
    // Called before canister upgrade
    // Save any state that needs to be preserved
}

#[post_upgrade]
fn post_upgrade() {
    // Called after canister upgrade
    // Restore any state that was saved
}

// Export the candid interface
ic_cdk::export_candid!();