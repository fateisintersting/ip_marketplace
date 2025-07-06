use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use std::cell::RefCell;
use candid::Principal;

use crate::types::*;

// Memory management
pub type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static IP_REGISTRY: RefCell<StableBTreeMap<String, IntellectualProperty, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    static NFT_REGISTRY: RefCell<StableBTreeMap<String, IPNft, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        )
    );

    static USER_REGISTRY: RefCell<StableBTreeMap<Principal, UserProfile, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
        )
    );

    static MARKETPLACE: RefCell<StableBTreeMap<String, MarketplaceListing, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
        )
    );

    static NFT_METADATA: RefCell<StableBTreeMap<String, NFTMetadata, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4))),
        )
    );

    static COUNTER: RefCell<u64> = RefCell::new(0);
}

// Storage access functions
pub fn with_ip_registry<R>(f: impl FnOnce(&StableBTreeMap<String, IntellectualProperty, Memory>) -> R) -> R {
    IP_REGISTRY.with(|registry| f(&registry.borrow()))
}

pub fn with_ip_registry_mut<R>(f: impl FnOnce(&mut StableBTreeMap<String, IntellectualProperty, Memory>) -> R) -> R {
    IP_REGISTRY.with(|registry| f(&mut registry.borrow_mut()))
}

pub fn with_nft_registry<R>(f: impl FnOnce(&StableBTreeMap<String, IPNft, Memory>) -> R) -> R {
    NFT_REGISTRY.with(|registry| f(&registry.borrow()))
}

pub fn with_nft_registry_mut<R>(f: impl FnOnce(&mut StableBTreeMap<String, IPNft, Memory>) -> R) -> R {
    NFT_REGISTRY.with(|registry| f(&mut registry.borrow_mut()))
}

pub fn with_user_registry<R>(f: impl FnOnce(&StableBTreeMap<Principal, UserProfile, Memory>) -> R) -> R {
    USER_REGISTRY.with(|registry| f(&registry.borrow()))
}

pub fn with_user_registry_mut<R>(f: impl FnOnce(&mut StableBTreeMap<Principal, UserProfile, Memory>) -> R) -> R {
    USER_REGISTRY.with(|registry| f(&mut registry.borrow_mut()))
}

pub fn with_marketplace<R>(f: impl FnOnce(&StableBTreeMap<String, MarketplaceListing, Memory>) -> R) -> R {
    MARKETPLACE.with(|registry| f(&registry.borrow()))
}

pub fn with_marketplace_mut<R>(f: impl FnOnce(&mut StableBTreeMap<String, MarketplaceListing, Memory>) -> R) -> R {
    MARKETPLACE.with(|registry| f(&mut registry.borrow_mut()))
}

pub fn with_nft_metadata<R>(f: impl FnOnce(&StableBTreeMap<String, NFTMetadata, Memory>) -> R) -> R {
    NFT_METADATA.with(|registry| f(&registry.borrow()))
}

pub fn with_nft_metadata_mut<R>(f: impl FnOnce(&mut StableBTreeMap<String, NFTMetadata, Memory>) -> R) -> R {
    NFT_METADATA.with(|registry| f(&mut registry.borrow_mut()))
}

pub fn with_counter<R>(f: impl FnOnce(&u64) -> R) -> R {
    COUNTER.with(|counter| f(&counter.borrow()))
}

pub fn with_counter_mut<R>(f: impl FnOnce(&mut u64) -> R) -> R {
    COUNTER.with(|counter| f(&mut counter.borrow_mut()))
}

// Helper function to generate unique IDs
pub fn generate_id(prefix: &str) -> String {
    with_counter_mut(|counter| {
        let current = *counter;
        *counter = current + 1;
        format!("{}_{}", prefix, current)
    })
}
