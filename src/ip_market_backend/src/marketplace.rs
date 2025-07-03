use ic_cdk::api::time;
use ic_cdk::{query, update};
use candid::Principal;

use crate::types::*;
use crate::storage::*;
use crate::user_management::*;

#[update]
pub fn list_nft_for_sale(request: ListNFTRequest) -> Result<MarketplaceListing> {
    let caller = ic_cdk::caller();
    let now = time();
    
    // Get NFT
    let nft = with_nft_registry(|registry| {
        registry.get(&request.nft_id)
    }).ok_or(IPMarketplaceError::NotFound)?;
    
    // Check ownership
    if nft.owner != caller {
        return Err(IPMarketplaceError::Unauthorized);
    }
    
    let listing_id = generate_id("LISTING");
    
    let auction_data = if request.is_auction {
        Some(AuctionData {
            starting_price: request.price,
            current_bid: request.price,
            highest_bidder: None,
            auction_end: now + request.auction_duration.unwrap_or(7 * 24 * 3600 * 1_000_000_000), // 7 days default
            min_bid_increment: request.min_bid_increment.unwrap_or(request.price / 100), // 1% default
        })
    } else {
        None
    };
    
    let listing = MarketplaceListing {
        id: listing_id.clone(),
        nft_id: request.nft_id,
        seller: caller,
        price: request.price,
        currency: request.currency,
        listed_at: now,
        expires_at: request.expires_at,
        status: if request.is_auction { ListingStatus::InAuction } else { ListingStatus::Active },
        license_terms: request.license_terms,
        auction_data,
    };
    
    with_marketplace_mut(|registry| {
        registry.insert(listing_id, listing.clone());
    });
    
    Ok(listing)
}

#[update]
pub fn place_bid(listing_id: String, bid_amount: u64) -> Result<bool> {
    let caller = ic_cdk::caller();
    let now = time();
    
    with_marketplace_mut(|marketplace| {
        if let Some(mut listing) = marketplace.get(&listing_id) {
            // Check if it's an auction
            if !matches!(listing.status, ListingStatus::InAuction) {
                return Err(IPMarketplaceError::InvalidInput);
            }
            
            if let Some(ref mut auction_data) = listing.auction_data {
                // Check if auction hasn't ended
                if now > auction_data.auction_end {
                    listing.status = ListingStatus::Expired;
                    marketplace.insert(listing_id, listing);
                    return Err(IPMarketplaceError::AuctionEnded);
                }
                
                // Check minimum bid
                let min_bid = auction_data.current_bid + auction_data.min_bid_increment;
                if bid_amount < min_bid {
                    return Err(IPMarketplaceError::BidTooLow);
                }
                
                // Update auction data
                auction_data.current_bid = bid_amount;
                auction_data.highest_bidder = Some(caller);
                
                marketplace.insert(listing_id, listing);
                Ok(true)
            } else {
                Err(IPMarketplaceError::InvalidInput)
            }
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

#[update]
pub fn buy_nft(listing_id: String) -> Result<bool> {
    let caller = ic_cdk::caller();
    let now = time();
    
    with_marketplace_mut(|marketplace| {
        if let Some(mut listing) = marketplace.get(&listing_id) {
            // Check if listing is active
            if !matches!(listing.status, ListingStatus::Active) {
                return Err(IPMarketplaceError::InvalidInput);
            }
            
            // Check if listing hasn't expired
            if let Some(expires_at) = listing.expires_at {
                if now > expires_at {
                    listing.status = ListingStatus::Expired;
                    marketplace.insert(listing_id, listing);
                    return Err(IPMarketplaceError::OperationFailed);
                }
            }
            
            // In a real implementation, you'd handle payment here
            // For now, we'll just simulate the transfer
            
            // Transfer NFT ownership
            let nft_id = listing.nft_id.clone();
            let seller = listing.seller;
            let price = listing.price;
            
            with_nft_registry_mut(|nft_registry| {
                if let Some(mut nft) = nft_registry.get(&nft_id) {
                    nft.owner = caller;
                    nft.transfer_history.push(TransferRecord {
                        from: seller,
                        to: caller,
                        timestamp: now,
                        transaction_hash: None,
                        price: Some(price),
                    });
                    nft_registry.insert(nft_id.clone(), nft);
                }
            });
            
            // Update user profiles
            remove_nft_from_user(seller, &nft_id);
            add_nft_to_user(caller, nft_id);
            update_user_sales_stats(seller, price, 0);
            update_user_sales_stats(caller, 0, price);
            
            // Mark listing as sold
            listing.status = ListingStatus::Sold;
            marketplace.insert(listing_id, listing);
            
            Ok(true)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

#[update]
pub fn cancel_listing(listing_id: String) -> Result<bool> {
    let caller = ic_cdk::caller();
    
    with_marketplace_mut(|marketplace| {
        if let Some(mut listing) = marketplace.get(&listing_id) {
            // Check ownership
            if listing.seller != caller {
                return Err(IPMarketplaceError::Unauthorized);
            }
            
            // Check if listing can be cancelled
            if matches!(listing.status, ListingStatus::Sold) {
                return Err(IPMarketplaceError::InvalidInput);
            }
            
            // For auctions, check if there are bids
            if let Some(ref auction_data) = listing.auction_data {
                if auction_data.highest_bidder.is_some() {
                    return Err(IPMarketplaceError::InvalidInput);
                }
            }
            
            listing.status = ListingStatus::Cancelled;
            marketplace.insert(listing_id, listing);
            Ok(true)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

#[query]
pub fn get_marketplace_listings() -> Vec<MarketplaceListing> {
    with_marketplace(|marketplace| {
        marketplace
            .iter()
            .filter(|(_, listing)| matches!(listing.status, ListingStatus::Active | ListingStatus::InAuction))
            .map(|(_, listing)| listing.clone())
            .collect()
    })
}

#[query]
pub fn get_listings_by_seller(seller: Principal) -> Vec<MarketplaceListing> {
    with_marketplace(|marketplace| {
        marketplace
            .iter()
            .filter(|(_, listing)| listing.seller == seller)
            .map(|(_, listing)| listing.clone())
            .collect()
    })
}

#[query]
pub fn get_marketplace_stats() -> MarketplaceStats {
    let mut total_listings = 0;
    let mut active_listings = 0;
    let mut total_volume = 0;
    let mut active_auctions = 0;
    
    with_marketplace(|marketplace| {
        for (_, listing) in marketplace.iter() {
            total_listings += 1;
            match listing.status {
                ListingStatus::Active => active_listings += 1,
                ListingStatus::InAuction => {
                    active_auctions += 1;
                    active_listings += 1;
                },
                ListingStatus::Sold => total_volume += listing.price,
                _ => {}
            }
        }
    });
    
    let total_nfts = with_nft_registry(|registry| registry.len() as u32);
    let total_users = with_user_registry(|registry| registry.len() as u32);
    
    MarketplaceStats {
        total_nfts,
        total_users,
        total_listings: total_listings as u32,
        active_listings: active_listings as u32,
        active_auctions: active_auctions as u32,
        total_volume,
        average_sale_price: if total_listings > 0 { Some(total_volume / total_listings) } else { None },
    }
}

#[query]
pub fn get_listing_by_id(listing_id: String) -> Result<MarketplaceListing> {
    with_marketplace(|marketplace| {
        marketplace.get(&listing_id)
    }).ok_or(IPMarketplaceError::NotFound)
}

#[query]
pub fn get_active_listings_by_nft(nft_id: String) -> Vec<MarketplaceListing> {
    with_marketplace(|marketplace| {
        marketplace
            .iter()
            .filter(|(_, listing)| {
                listing.nft_id == nft_id && 
                matches!(listing.status, ListingStatus::Active | ListingStatus::InAuction)
            })
            .map(|(_, listing)| listing.clone())
            .collect()
    })
}

#[query]
pub fn get_expired_listings() -> Vec<MarketplaceListing> {
    let now = time();
    with_marketplace(|marketplace| {
        marketplace
            .iter()
            .filter(|(_, listing)| {
                if let Some(expires_at) = listing.expires_at {
                    now > expires_at && matches!(listing.status, ListingStatus::Active)
                } else {
                    false
                }
            })
            .map(|(_, listing)| listing.clone())
            .collect()
    })
}

// Admin function to clean up expired listings
#[update]
pub fn cleanup_expired_listings() -> Result<u32> {
    let now = time();
    let mut cleaned_count = 0;
    
    with_marketplace_mut(|marketplace| {
        let expired_ids: Vec<String> = marketplace
            .iter()
            .filter(|(_, listing)| {
                if let Some(expires_at) = listing.expires_at {
                    now > expires_at && matches!(listing.status, ListingStatus::Active)
                } else {
                    false
                }
            })
            .map(|(id, _)| id.clone())
            .collect();
        
        for id in expired_ids {
            if let Some(mut listing) = marketplace.get(&id) {
                listing.status = ListingStatus::Expired;
                marketplace.insert(id, listing);
                cleaned_count += 1;
            }
        }
    });
    
    Ok(cleaned_count)
}
