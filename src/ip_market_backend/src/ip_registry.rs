use ic_cdk::api::time;
use ic_cdk::{query, update};
use candid::Principal;

use crate::types::*;
use crate::storage::*;
use crate::utils::*;

#[update]
pub fn register_ip(request: RegisterIPRequest) -> Result<IntellectualProperty> {
    let caller = ic_cdk::caller();
    let now = time();
    
    // Validate image URL if provided
    if let Some(ref url) = request.image_url {
        if !validate_image_url(url) {
            return Err(IPMarketplaceError::InvalidInput);
        }
    }
    
    // Generate unique ID for the IP
    let ip_id = generate_id("IP");
    
    // Create IP record
    let ip = IntellectualProperty {
        id: ip_id.clone(),
        title: request.title,
        description: request.description,
        ip_type: request.ip_type,
        owner: caller,
        creator: caller,
        creation_date: now,
        registration_date: now,
        metadata: request.metadata,
        verification_status: VerificationStatus::Pending,
        nft_id: None,
        image_url: request.image_url,
        additional_files: request.additional_files,
    };
    
    // Store in registry
    with_ip_registry_mut(|registry| {
        registry.insert(ip_id.clone(), ip.clone());
    });
    
    // Update user profile
    with_user_registry_mut(|registry| {
        if let Some(mut user) = registry.get(&caller) {
            user.owned_ips.push(ip_id);
            registry.insert(caller, user);
        }
    });
    
    Ok(ip)
}

#[query]
pub fn get_ip_by_id(ip_id: String) -> Result<IntellectualProperty> {
    with_ip_registry(|registry| {
        registry.get(&ip_id)
    }).ok_or(IPMarketplaceError::NotFound)
}

#[query]
pub fn get_user_ips(user: Principal) -> Vec<IntellectualProperty> {
    with_ip_registry(|registry| {
        registry
            .iter()
            .filter(|(_, ip)| ip.owner == user)
            .map(|(_, ip)| ip.clone())
            .collect()
    })
}

#[query]
pub fn search_ips(query: String, ip_type: Option<IPType>) -> Vec<IntellectualProperty> {
    let query_lower = query.to_lowercase();
    
    with_ip_registry(|registry| {
        registry
            .iter()
            .filter(|(_, ip)| {
                let matches_query = ip.title.to_lowercase().contains(&query_lower) ||
                                  ip.description.to_lowercase().contains(&query_lower) ||
                                  ip.metadata.tags.iter().any(|tag| tag.to_lowercase().contains(&query_lower));
                
                let matches_type = match &ip_type {
                    Some(t) => std::mem::discriminant(&ip.ip_type) == std::mem::discriminant(t),
                    None => true,
                };
                
                matches_query && matches_type
            })
            .map(|(_, ip)| ip.clone())
            .collect()
    })
}

#[update]
pub fn verify_ip(ip_id: String, status: VerificationStatus) -> Result<bool> {
    // In production, this should check for admin privileges
    with_ip_registry_mut(|registry| {
        if let Some(mut ip) = registry.get(&ip_id) {
            ip.verification_status = status;
            registry.insert(ip_id, ip);
            Ok(true)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}
