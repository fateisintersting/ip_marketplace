use ic_cdk::api::time;
use ic_cdk::{query, update};
use candid::Principal;

use crate::types::*;
use crate::storage::*;
use crate::utils::*;

#[update]
pub fn mint_ip_nft(request: MintNFTRequest) -> Result<IPNft> {
    let caller = ic_cdk::caller();
    let now = time();
    
    // Get IP record
    let ip = with_ip_registry(|registry| {
        registry.get(&request.ip_id)
    }).ok_or(IPMarketplaceError::NotFound)?;
    
    // Check ownership
    if ip.owner != caller {
        return Err(IPMarketplaceError::Unauthorized);
    }
    
    // Check if NFT already exists
    if ip.nft_id.is_some() {
        return Err(IPMarketplaceError::AlreadyExists);
    }
    
    // Validate image URL
    if !validate_image_url(&request.image) {
        return Err(IPMarketplaceError::InvalidInput);
    }
    
    let nft_id = generate_id("NFT");
    
    // Generate token ID
    let token_id = with_counter_mut(|counter| {
        let current = *counter;
        *counter = current + 1;
        current
    });
    
    // Calculate rarity score
    let rarity_score = calculate_rarity_score(&request.attributes);
    
    // Create comprehensive NFT metadata
    let metadata = NFTMetadata {
        token_id: nft_id.clone(),
        name: request.name.clone(),
        description: request.description.clone(),
        image: request.image.clone(),
        external_url: request.external_url,
        animation_url: request.animation_url,
        background_color: request.background_color,
        attributes: request.attributes,
        ip_category: ip.metadata.category.clone(),
        ip_type: format!("{:?}", ip.ip_type),
        creator: caller.to_string(),
        creation_date: format_timestamp(ip.creation_date),
        jurisdiction: Some(ip.metadata.jurisdiction.clone()),
        license_type: None, // To be set based on license terms
        file_type: Some("image/png".to_string()), // Default, should be detected
        file_size: None,
        resolution: None,
        duration: None,
        minted_date: format_timestamp(now),
        blockchain: "Internet Computer".to_string(),
        token_standard: "ICRC-7".to_string(),
    };
    
    // Store metadata
    with_nft_metadata_mut(|registry| {
        registry.insert(nft_id.clone(), metadata);
    });
    
    // Create NFT
    let nft = IPNft {
        id: nft_id.clone(),
        ip_id: request.ip_id.clone(),
        token_id,
        owner: caller,
        creator: caller,
        metadata_uri: format!("ic://{}/metadata/{}", ic_cdk::id(), nft_id),
        minted_at: now,
        royalty_percentage: request.royalty_percentage.unwrap_or(10),
        is_transferable: true,
        name: request.name,
        description: request.description,
        image: request.image,
        collection_name: request.collection_name,
        edition_number: request.edition_number,
        total_editions: request.total_editions,
        rarity_rank: None, // To be calculated globally
        rarity_score: Some(rarity_score),
        transfer_history: vec![TransferRecord {
            from: Principal::anonymous(),
            to: caller,
            timestamp: now,
            transaction_hash: None,
            price: None,
        }],
        view_count: 0,
        favorite_count: 0,
    };
    
    // Store NFT
    with_nft_registry_mut(|registry| {
        registry.insert(nft_id.clone(), nft.clone());
    });
    
    // Update IP record with NFT ID
    with_ip_registry_mut(|registry| {
        let mut updated_ip = ip;
        updated_ip.nft_id = Some(nft_id.clone());
        registry.insert(request.ip_id, updated_ip);
    });
    
    // Update user profile
    with_user_registry_mut(|registry| {
        if let Some(mut user) = registry.get(&caller) {
            user.owned_nfts.push(nft_id);
            registry.insert(caller, user);
        }
    });
    
    Ok(nft)
}

#[update]
pub fn transfer_nft(nft_id: String, to: Principal) -> Result<bool> {
    let caller = ic_cdk::caller();
    let now = time();
    
    // Get NFT
    let mut nft = with_nft_registry(|registry| {
        registry.get(&nft_id)
    }).ok_or(IPMarketplaceError::NotFound)?;
    
    // Check ownership and transferability
    if nft.owner != caller {
        return Err(IPMarketplaceError::Unauthorized);
    }
    
    if !nft.is_transferable {
        return Err(IPMarketplaceError::NFTNotTransferable);
    }
    
    // Update NFT ownership
    nft.owner = to;
    nft.transfer_history.push(TransferRecord {
        from: caller,
        to,
        timestamp: now,
        transaction_hash: None,
        price: None,
    });
    
    // Update registries
    with_nft_registry_mut(|registry| {
        registry.insert(nft_id.clone(), nft);
    });
    
    // Update user profiles
    with_user_registry_mut(|registry| {
        // Remove from sender
        if let Some(mut sender) = registry.get(&caller) {
            sender.owned_nfts.retain(|id| id != &nft_id);
            registry.insert(caller, sender);
        }
        
        // Add to receiver
        if let Some(mut receiver) = registry.get(&to) {
            receiver.owned_nfts.push(nft_id);
            registry.insert(to, receiver);
        }
    });
    
    Ok(true)
}

#[query]
pub fn get_nft_metadata(nft_id: String) -> Result<NFTMetadata> {
    with_nft_metadata(|registry| {
        registry.get(&nft_id)
    }).ok_or(IPMarketplaceError::NotFound)
}

#[query]
pub fn get_nft_full_details(nft_id: String) -> Result<(IPNft, NFTMetadata, IntellectualProperty)> {
    let nft = with_nft_registry(|registry| {
        registry.get(&nft_id)
    }).ok_or(IPMarketplaceError::NotFound)?;
    
    let metadata = with_nft_metadata(|registry| {
        registry.get(&nft_id)
    }).ok_or(IPMarketplaceError::NotFound)?;
    
    let ip = with_ip_registry(|registry| {
        registry.get(&nft.ip_id)
    }).ok_or(IPMarketplaceError::NotFound)?;
    
    Ok((nft, metadata, ip))
}

#[query]
pub fn get_nft_by_id(nft_id: String) -> Result<IPNft> {
    with_nft_registry(|registry| {
        registry.get(&nft_id)
    }).ok_or(IPMarketplaceError::NotFound)
}

#[query]
pub fn get_user_nfts(user: Principal) -> Vec<IPNft> {
    with_nft_registry(|registry| {
        registry
            .iter()
            .filter(|(_, nft)| nft.owner == user)
            .map(|(_, nft)| nft.clone())
            .collect()
    })
}

#[query]
pub fn get_trending_nfts(limit: usize) -> Vec<IPNft> {
    with_nft_registry(|registry| {
        let mut nfts: Vec<IPNft> = registry
            .iter()
            .map(|(_, nft)| nft.clone())
            .collect();
        
        // Sort by view count + favorite count for trending
        nfts.sort_by(|a, b| (b.view_count + b.favorite_count).cmp(&(a.view_count + a.favorite_count)));
        nfts.truncate(limit);
        nfts
    })
}

#[query]
pub fn search_nfts(query: String, filters: NFTSearchFilters) -> Vec<IPNft> {
    let query_lower = query.to_lowercase();
    
    with_nft_registry(|registry| {
        registry
            .iter()
            .filter(|(_, nft)| {
                let matches_query = nft.name.to_lowercase().contains(&query_lower) ||
                                  nft.description.to_lowercase().contains(&query_lower);
                
                let matches_collection = match &filters.collection_name {
                    Some(collection) => nft.collection_name.as_ref().map_or(false, |c| c == collection),
                    None => true,
                };
                
                let matches_price_range = match (filters.min_price, filters.max_price) {
                    (Some(min), Some(max)) => {
                        // Check if NFT is listed in marketplace within price range
                        with_marketplace(|marketplace| {
                            marketplace
                                .iter()
                                .any(|(_, listing)| {
                                    listing.nft_id == nft.id && 
                                    listing.price >= min && 
                                    listing.price <= max &&
                                    matches!(listing.status, ListingStatus::Active | ListingStatus::InAuction)
                                })
                        })
                    },
                    (Some(min), None) => {
                        with_marketplace(|marketplace| {
                            marketplace
                                .iter()
                                .any(|(_, listing)| {
                                    listing.nft_id == nft.id && 
                                    listing.price >= min &&
                                    matches!(listing.status, ListingStatus::Active | ListingStatus::InAuction)
                                })
                        })
                    },
                    (None, Some(max)) => {
                        with_marketplace(|marketplace| {
                            marketplace
                                .iter()
                                .any(|(_, listing)| {
                                    listing.nft_id == nft.id && 
                                    listing.price <= max &&
                                    matches!(listing.status, ListingStatus::Active | ListingStatus::InAuction)
                                })
                        })
                    },
                    (None, None) => true,
                };
                
                matches_query && matches_collection && matches_price_range
            })
            .map(|(_, nft)| nft.clone())
            .collect()
    })
}

#[query]
pub fn get_nft_collection_stats(collection_name: String) -> CollectionStats {
    let nfts: Vec<IPNft> = with_nft_registry(|registry| {
        registry
            .iter()
            .filter(|(_, nft)| nft.collection_name.as_ref().map_or(false, |c| c == &collection_name))
            .map(|(_, nft)| nft.clone())
            .collect()
    });
    
    let total_supply = nfts.len() as u32;
    let unique_owners = nfts.iter()
        .map(|nft| nft.owner)
        .collect::<std::collections::HashSet<_>>()
        .len() as u32;
    
    // Get floor price from marketplace
    let floor_price = with_marketplace(|marketplace| {
        marketplace
            .iter()
            .filter(|(_, listing)| {
                matches!(listing.status, ListingStatus::Active) &&
                nfts.iter().any(|nft| nft.id == listing.nft_id)
            })
            .map(|(_, listing)| listing.price)
            .min()
    });
    
    // Calculate total volume (simplified)
    let total_volume = nfts.iter()
        .flat_map(|nft| &nft.transfer_history)
        .filter_map(|transfer| transfer.price)
        .sum();
    
    CollectionStats {
        collection_name,
        total_supply,
        unique_owners,
        floor_price,
        total_volume,
        average_price: if total_supply > 0 { Some(total_volume / total_supply as u64) } else { None },
    }
}

#[update]
pub fn increment_nft_view(nft_id: String) -> Result<u64> {
    with_nft_registry_mut(|registry| {
        if let Some(mut nft) = registry.get(&nft_id) {
            nft.view_count += 1;
            let new_count = nft.view_count;
            registry.insert(nft_id, nft);
            Ok(new_count)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

#[update]
pub fn toggle_nft_favorite(nft_id: String) -> Result<u64> {
    let _caller = ic_cdk::caller();
    
    // In a real implementation, you'd track individual user favorites
    // For simplicity, we're just incrementing/decrementing the total count
    with_nft_registry_mut(|registry| {
        if let Some(mut nft) = registry.get(&nft_id) {
            nft.favorite_count += 1; // In reality, check if user already favorited
            let new_count = nft.favorite_count;
            registry.insert(nft_id, nft);
            Ok(new_count)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

#[query]
pub fn get_nft_history(nft_id: String) -> Result<Vec<TransferRecord>> {
    with_nft_registry(|registry| {
        registry
            .get(&nft_id)
            .map(|nft| nft.transfer_history.clone())
    }).ok_or(IPMarketplaceError::NotFound)
}

#[query]
pub fn get_nfts_batch(nft_ids: Vec<String>) -> Vec<Option<IPNft>> {
    with_nft_registry(|registry| {
        nft_ids.into_iter()
            .map(|id| registry.get(&id))
            .collect()
    })
}
