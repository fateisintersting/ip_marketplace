use ic_cdk::api::time;
use ic_cdk::{query, update};
use candid::Principal;

use crate::types::*;
use crate::storage::*;

#[update]
pub fn create_user_profile(request: CreateUserRequest) -> Result<UserProfile> {
    let caller = ic_cdk::caller();
    let now = time();
    
    // Check if user already exists
    let exists = with_user_registry(|registry| {
        registry.contains_key(&caller)
    });
    
    if exists {
        return Err(IPMarketplaceError::AlreadyExists);
    }
    
    let user = UserProfile {
        principal: caller,
        username: request.username,
        email: request.email,
        bio: request.bio,
        reputation_score: 0,
        verified: false,
        created_at: now,
        owned_ips: Vec::new(),
        owned_nfts: Vec::new(),
        avatar_url: request.avatar_url,
        banner_url: request.banner_url,
        social_links: request.social_links,
        total_sales: 0,
        total_purchases: 0,
    };
    
    with_user_registry_mut(|registry| {
        registry.insert(caller, user.clone());
    });
    
    Ok(user)
}

#[query]
pub fn get_user_profile(user: Principal) -> Result<UserProfile> {
    with_user_registry(|registry| {
        registry.get(&user)
    }).ok_or(IPMarketplaceError::NotFound)
}

#[query]
pub fn get_my_profile() -> Result<UserProfile> {
    let caller = ic_cdk::caller();
    get_user_profile(caller)
}

#[update]
pub fn update_user_reputation(user: Principal, score_change: i32) -> Result<u32> {
    // In production, this should check for admin privileges
    with_user_registry_mut(|registry| {
        if let Some(mut user_profile) = registry.get(&user) {
            if score_change < 0 && (-score_change) as u32 > user_profile.reputation_score {
                user_profile.reputation_score = 0;
            } else {
                user_profile.reputation_score = (user_profile.reputation_score as i32 + score_change) as u32;
            }
            let new_score = user_profile.reputation_score;
            registry.insert(user, user_profile);
            Ok(new_score)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

#[update]
pub fn update_user_profile(request: UpdateUserRequest) -> Result<UserProfile> {
    let caller = ic_cdk::caller();
    
    with_user_registry_mut(|registry| {
        if let Some(mut user_profile) = registry.get(&caller) {
            // Update fields if provided
            if let Some(username) = request.username {
                user_profile.username = username;
            }
            if let Some(email) = request.email {
                user_profile.email = Some(email);
            }
            if let Some(bio) = request.bio {
                user_profile.bio = Some(bio);
            }
            if let Some(avatar_url) = request.avatar_url {
                user_profile.avatar_url = Some(avatar_url);
            }
            if let Some(banner_url) = request.banner_url {
                user_profile.banner_url = Some(banner_url);
            }
            if let Some(social_links) = request.social_links {
                user_profile.social_links = social_links;
            }
            
            registry.insert(caller, user_profile.clone());
            Ok(user_profile)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

// Helper function to update user sales/purchases (used by marketplace)
pub fn update_user_sales_stats(user: Principal, sales_amount: u64, purchases_amount: u64) {
    with_user_registry_mut(|registry| {
        if let Some(mut user_profile) = registry.get(&user) {
            user_profile.total_sales += sales_amount;
            user_profile.total_purchases += purchases_amount;
            registry.insert(user, user_profile);
        }
    });
}

// Helper function to add/remove NFT from user profile (used by NFT management)
pub fn add_nft_to_user(user: Principal, nft_id: String) {
    with_user_registry_mut(|registry| {
        if let Some(mut user_profile) = registry.get(&user) {
            if !user_profile.owned_nfts.contains(&nft_id) {
                user_profile.owned_nfts.push(nft_id);
                registry.insert(user, user_profile);
            }
        }
    });
}

pub fn remove_nft_from_user(user: Principal, nft_id: &str) {
    with_user_registry_mut(|registry| {
        if let Some(mut user_profile) = registry.get(&user) {
            user_profile.owned_nfts.retain(|id| id != nft_id);
            registry.insert(user, user_profile);
        }
    });
}

// Helper function to add/remove IP from user profile (used by IP registry)
pub fn add_ip_to_user(user: Principal, ip_id: String) {
    with_user_registry_mut(|registry| {
        if let Some(mut user_profile) = registry.get(&user) {
            if !user_profile.owned_ips.contains(&ip_id) {
                user_profile.owned_ips.push(ip_id);
                registry.insert(user, user_profile);
            }
        }
    });
}

pub fn remove_ip_from_user(user: Principal, ip_id: &str) {
    with_user_registry_mut(|registry| {
        if let Some(mut user_profile) = registry.get(&user) {
            user_profile.owned_ips.retain(|id| id != ip_id);
            registry.insert(user, user_profile);
        }
    });
}
