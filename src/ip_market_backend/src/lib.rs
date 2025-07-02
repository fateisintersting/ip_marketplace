use ic_cdk::api::time;
use ic_cdk::{init, post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, Storable};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;
use candid::{CandidType, Principal};
use sha2::{Digest, Sha256};
use ic_stable_structures::storable::Bound;

// Memory management
type Memory = VirtualMemory<DefaultMemoryImpl>;

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

// Enhanced NFT Metadata structure following ERC-721 and ERC-1155 standards
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct NFTMetadata {
    pub token_id: String,
    // Core NFT fields
    pub name: String,
    pub description: String,
    pub image: String, // URL or IPFS hash
    pub external_url: Option<String>,
    
    // Additional media
    pub animation_url: Option<String>, // For videos, audio, etc.
    pub background_color: Option<String>, // Hex color without #
    
    // Attributes for rarity and properties
    pub attributes: Vec<NFTAttribute>,
    
    // IP-specific metadata
    pub ip_category: String,
    pub ip_type: String,
    pub creator: String,
    pub creation_date: String,
    pub jurisdiction: Option<String>,
    pub license_type: Option<String>,
    
    // Technical metadata
    pub file_type: Option<String>, // image/png, video/mp4, etc.
    pub file_size: Option<u64>,
    pub resolution: Option<String>, // "1920x1080"
    pub duration: Option<u64>, // For videos/audio in seconds
    
    // Blockchain metadata
    pub minted_date: String,
    pub blockchain: String,
    pub token_standard: String, // "ERC-721", "ICRC-7", etc.
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct NFTAttribute {
    pub trait_type: String,
    pub value: AttributeValue,
    pub display_type: Option<String>, // "number", "boost_number", "boost_percentage", "date"
    pub max_value: Option<f64>, // For progress bars
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum AttributeValue {
    Text(String),
    Number(f64),
    Boolean(bool),
}

// Data structures
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct IntellectualProperty {
    pub id: String,
    pub title: String,
    pub description: String,
    pub ip_type: IPType,
    pub owner: Principal,
    pub creator: Principal,
    pub creation_date: u64,
    pub registration_date: u64,
    pub metadata: IPMetadata,
    pub verification_status: VerificationStatus,
    pub nft_id: Option<String>,
    // Enhanced fields for NFT creation
    pub image_url: Option<String>,
    pub additional_files: Vec<FileMetadata>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct FileMetadata {
    pub file_name: String,
    pub file_type: String,
    pub file_size: u64,
    pub file_hash: String,
    pub file_url: String, // IPFS or other storage URL
    pub uploaded_at: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum IPType {
    Patent,
    Trademark,
    Copyright,
    TradeSecret,
    Design,
    DigitalArt,
    Music,
    Literature,
    Software,
    Photography,
    Video,
    Other(String),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct IPMetadata {
    pub category: String,
    pub tags: Vec<String>,
    pub file_hash: Option<String>,
    pub file_url: Option<String>,
    pub jurisdiction: String,
    pub expiry_date: Option<u64>,
    pub priority_date: Option<u64>,
    pub application_number: Option<String>,
    pub registration_number: Option<String>,
    // Enhanced metadata
    pub genre: Option<String>,
    pub medium: Option<String>,
    pub dimensions: Option<String>,
    pub color_palette: Vec<String>,
    pub software_used: Vec<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum VerificationStatus {
    Pending,
    Verified,
    Rejected,
    UnderReview,
}

// Enhanced NFT structure
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct IPNft {
    pub id: String,
    pub ip_id: String,
    pub token_id: u64,
    pub owner: Principal,
    pub creator: Principal,
    pub metadata_uri: String,
    pub minted_at: u64,
    pub royalty_percentage: u8, // 0-100
    pub is_transferable: bool,
    
    // Enhanced NFT fields
    pub name: String,
    pub description: String,
    pub image: String,
    pub collection_name: Option<String>,
    pub edition_number: Option<u32>,
    pub total_editions: Option<u32>,
    pub rarity_rank: Option<u32>,
    pub rarity_score: Option<f64>,
    
    // Transfer history
    pub transfer_history: Vec<TransferRecord>,
    pub view_count: u64,
    pub favorite_count: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TransferRecord {
    pub from: Principal,
    pub to: Principal,
    pub timestamp: u64,
    pub transaction_hash: Option<String>,
    pub price: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct UserProfile {
    pub principal: Principal,
    pub username: String,
    pub email: Option<String>,
    pub bio: Option<String>,
    pub reputation_score: u32,
    pub verified: bool,
    pub created_at: u64,
    pub owned_ips: Vec<String>,
    pub owned_nfts: Vec<String>,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub social_links: Vec<SocialLink>,
    pub total_sales: u64,
    pub total_purchases: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SocialLink {
    pub url: String,
    pub platform: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct MarketplaceListing {
    pub id: String,
    pub nft_id: String,
    pub seller: Principal,
    pub price: u64, // in e8s (ICP smallest unit)
    pub currency: String, // "ICP" initially
    pub listed_at: u64,
    pub expires_at: Option<u64>,
    pub status: ListingStatus,
    pub license_terms: Option<LicenseTerms>,
    pub auction_data: Option<AuctionData>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct AuctionData {
    pub starting_price: u64,
    pub current_bid: u64,
    pub highest_bidder: Option<Principal>,
    pub auction_end: u64,
    pub min_bid_increment: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum ListingStatus {
    Active,
    Sold,
    Cancelled,
    Expired,
    InAuction,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct LicenseTerms {
    pub usage_rights: Vec<String>,
    pub duration: Option<u64>, // in nanoseconds
    pub territory: Option<String>,
    pub exclusivity: bool,
    pub commercial_use: bool,
    pub modification_rights: bool,
    pub attribution_required: bool,
}

// Enhanced Request types
#[derive(CandidType, Serialize, Deserialize)]
pub struct RegisterIPRequest {
    pub title: String,
    pub description: String,
    pub ip_type: IPType,
    pub metadata: IPMetadata,
    pub image_url: Option<String>,
    pub additional_files: Vec<FileMetadata>,
}

#[derive(CandidType, Serialize, Deserialize)]
pub struct MintNFTRequest {
    pub ip_id: String,
    pub name: String,
    pub description: String,
    pub image: String,
    pub attributes: Vec<NFTAttribute>,
    pub collection_name: Option<String>,
    pub edition_number: Option<u32>,
    pub total_editions: Option<u32>,
    pub royalty_percentage: Option<u8>,
    pub external_url: Option<String>,
    pub animation_url: Option<String>,
    pub background_color: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub bio: Option<String>,
    pub username: String,
    pub banner_url: Option<String>,
    pub avatar_url: Option<String>,
    pub email: Option<String>,
    pub social_links: Vec<SocialLink>,
}

#[derive(CandidType, Serialize, Deserialize)]
pub struct ListNFTRequest {
    pub nft_id: String,
    pub price: u64,
    pub currency: String,
    pub expires_at: Option<u64>,
    pub license_terms: Option<LicenseTerms>,
    pub is_auction: bool,
    pub auction_duration: Option<u64>,
    pub min_bid_increment: Option<u64>,
}

// Error types
#[derive(CandidType, Serialize, Deserialize, Debug)]
pub enum IPMarketplaceError {
    NotFound,
    Unauthorized,
    AlreadyExists,
    InvalidInput,
    InsufficientFunds,
    OperationFailed,
    NotImplemented,
    InvalidFileFormat,
    FileTooLarge,
    AuctionEnded,
    BidTooLow,
    NFTNotTransferable,
}

type Result<T> = std::result::Result<T, IPMarketplaceError>;

// Storable implementations
impl Storable for IntellectualProperty {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for IPNft {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for UserProfile {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).unwrap_or_else(|_| {
            // Return a default UserProfile if decoding fails
            UserProfile {
                principal: Principal::anonymous(),
                username: "unknown".to_string(),
                email: None,
                bio: None,
                reputation_score: 0,
                verified: false,
                created_at: 0,
                owned_ips: Vec::new(),
                owned_nfts: Vec::new(),
                avatar_url: None,
                banner_url: None,
                social_links: Vec::new(),
                total_sales: 0,
                total_purchases: 0,
            }
        })
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for MarketplaceListing {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for NFTMetadata {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}

// Utility functions
fn generate_id(prefix: &str) -> String {
    COUNTER.with(|counter| {
        let current = *counter.borrow();
        *counter.borrow_mut() = current + 1;
        format!("{}_{}", prefix, current)
    })
}

fn generate_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

fn format_timestamp(timestamp: u64) -> String {
    // Convert nanoseconds to a readable format
    // This is a simplified version - in production, use proper date formatting
    format!("{}", timestamp / 1_000_000_000) // Convert to seconds
}

fn validate_image_url(url: &str) -> bool {
    // Basic validation for image URLs
    url.starts_with("http://") || url.starts_with("https://") || url.starts_with("ipfs://")
}

fn calculate_rarity_score(attributes: &[NFTAttribute]) -> f64 {
    // Simple rarity calculation - in production, this would be more sophisticated
    let mut score = 0.0;
    for attr in attributes {
        match &attr.value {
            AttributeValue::Number(n) => score += n / 100.0,
            AttributeValue::Text(t) => score += t.len() as f64 / 50.0,
            AttributeValue::Boolean(b) => score += if *b { 1.0 } else { 0.5 },
        }
    }
    score
}

// Core functions
#[update]
fn register_ip(request: RegisterIPRequest) -> Result<IntellectualProperty> {
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
    IP_REGISTRY.with(|registry| {
        registry.borrow_mut().insert(ip_id.clone(), ip.clone());
    });
    
    // Update user profile
    USER_REGISTRY.with(|registry| {
        let mut users = registry.borrow_mut();
        if let Some(mut user) = users.get(&caller) {
            user.owned_ips.push(ip_id);
            users.insert(caller, user);
        }
    });
    
    Ok(ip)
}

#[update]
fn mint_ip_nft(request: MintNFTRequest) -> Result<IPNft> {
    let caller = ic_cdk::caller();
    let now = time();
    
    // Get IP record
    let ip = IP_REGISTRY.with(|registry| {
        registry.borrow().get(&request.ip_id)
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
    let token_id = COUNTER.with(|counter| {
        let current = *counter.borrow();
        *counter.borrow_mut() = current + 1;
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
    NFT_METADATA.with(|registry| {
        registry.borrow_mut().insert(nft_id.clone(), metadata);
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
    NFT_REGISTRY.with(|registry| {
        registry.borrow_mut().insert(nft_id.clone(), nft.clone());
    });
    
    // Update IP record with NFT ID
    IP_REGISTRY.with(|registry| {
        let mut ips = registry.borrow_mut();
        let mut updated_ip = ip;
        updated_ip.nft_id = Some(nft_id.clone());
        ips.insert(request.ip_id, updated_ip);
    });
    
    // Update user profile
    USER_REGISTRY.with(|registry| {
        let mut users = registry.borrow_mut();
        if let Some(mut user) = users.get(&caller) {
            user.owned_nfts.push(nft_id);
            users.insert(caller, user);
        }
    });
    
    Ok(nft)
}

#[update]
fn transfer_nft(nft_id: String, to: Principal) -> Result<bool> {
    let caller = ic_cdk::caller();
    let now = time();
    
    // Get NFT
    let mut nft = NFT_REGISTRY.with(|registry| {
        registry.borrow().get(&nft_id)
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
    NFT_REGISTRY.with(|registry| {
        registry.borrow_mut().insert(nft_id.clone(), nft);
    });
    
    // Update user profiles
    USER_REGISTRY.with(|registry| {
        let mut users = registry.borrow_mut();
        
        // Remove from sender
        if let Some(mut sender) = users.get(&caller) {
            sender.owned_nfts.retain(|id| id != &nft_id);
            users.insert(caller, sender);
        }
        
        // Add to receiver
        if let Some(mut receiver) = users.get(&to) {
            receiver.owned_nfts.push(nft_id);
            users.insert(to, receiver);
        }
    });
    
    Ok(true)
}

#[update]
fn create_user_profile(request: CreateUserRequest) -> Result<UserProfile> {
    let caller = ic_cdk::caller();
    let now = time();
    
    // Check if user already exists
    let exists = USER_REGISTRY.with(|registry| {
        registry.borrow().contains_key(&caller)
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
    
    USER_REGISTRY.with(|registry| {
        registry.borrow_mut().insert(caller, user.clone());
    });
    
    Ok(user)
}

#[update]
fn list_nft_for_sale(request: ListNFTRequest) -> Result<MarketplaceListing> {
    let caller = ic_cdk::caller();
    let now = time();
    
    // Get NFT
    let nft = NFT_REGISTRY.with(|registry| {
        registry.borrow().get(&request.nft_id)
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
    
    MARKETPLACE.with(|registry| {
        registry.borrow_mut().insert(listing_id, listing.clone());
    });
    
    Ok(listing)
}

// Enhanced Query functions
#[query]
fn get_nft_metadata(nft_id: String) -> Result<NFTMetadata> {
    NFT_METADATA.with(|registry| {
        registry.borrow().get(&nft_id)
    }).ok_or(IPMarketplaceError::NotFound)
}

#[query]
fn get_nft_full_details(nft_id: String) -> Result<(IPNft, NFTMetadata, IntellectualProperty)> {
    let nft = NFT_REGISTRY.with(|registry| {
        registry.borrow().get(&nft_id)
    }).ok_or(IPMarketplaceError::NotFound)?;
    
    let metadata = NFT_METADATA.with(|registry| {
        registry.borrow().get(&nft_id)
    }).ok_or(IPMarketplaceError::NotFound)?;
    
    let ip = IP_REGISTRY.with(|registry| {
        registry.borrow().get(&nft.ip_id)
    }).ok_or(IPMarketplaceError::NotFound)?;
    
    Ok((nft, metadata, ip))
}

#[query]
fn get_ip_by_id(ip_id: String) -> Result<IntellectualProperty> {
    IP_REGISTRY.with(|registry| {
        registry.borrow().get(&ip_id)
    }).ok_or(IPMarketplaceError::NotFound)
}

#[query]
fn get_nft_by_id(nft_id: String) -> Result<IPNft> {
    NFT_REGISTRY.with(|registry| {
        registry.borrow().get(&nft_id)
    }).ok_or(IPMarketplaceError::NotFound)
}

#[query]
fn get_user_profile(user: Principal) -> Result<UserProfile> {
    USER_REGISTRY.with(|registry| {
        registry.borrow().get(&user)
    }).ok_or(IPMarketplaceError::NotFound)
}

#[query]
fn get_my_profile() -> Result<UserProfile> {
    let caller = ic_cdk::caller();
    get_user_profile(caller)
}

#[query]
fn get_marketplace_listings() -> Vec<MarketplaceListing> {
    MARKETPLACE.with(|registry| {
        registry.borrow()
            .iter()
            .filter(|(_, listing)| matches!(listing.status, ListingStatus::Active | ListingStatus::InAuction))
            .map(|(_, listing)| listing.clone())
            .collect()
    })
}

#[query]
fn get_trending_nfts(limit: usize) -> Vec<IPNft> {
    NFT_REGISTRY.with(|registry| {
        let mut nfts: Vec<IPNft> = registry.borrow()
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
fn get_user_ips(user: Principal) -> Vec<IntellectualProperty> {
    IP_REGISTRY.with(|registry| {
        registry.borrow()
            .iter()
            .filter(|(_, ip)| ip.owner == user)
            .map(|(_, ip)| ip.clone())
            .collect()
    })
}

#[query]
fn get_user_nfts(user: Principal) -> Vec<IPNft> {
    NFT_REGISTRY.with(|registry| {
        registry.borrow()
            .iter()
            .filter(|(_, nft)| nft.owner == user)
            .map(|(_, nft)| nft.clone())
            .collect()
    })
}

#[query]
fn search_ips(query: String, ip_type: Option<IPType>) -> Vec<IntellectualProperty> {
    let query_lower = query.to_lowercase();
    
    IP_REGISTRY.with(|registry| {
        registry.borrow()
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

#[query]
fn search_nfts(query: String, filters: NFTSearchFilters) -> Vec<IPNft> {
    let query_lower = query.to_lowercase();
    
    NFT_REGISTRY.with(|registry| {
        registry.borrow()
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
                        MARKETPLACE.with(|marketplace| {
                            marketplace.borrow()
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
                        MARKETPLACE.with(|marketplace| {
                            marketplace.borrow()
                                .iter()
                                .any(|(_, listing)| {
                                    listing.nft_id == nft.id && 
                                    listing.price >= min &&
                                    matches!(listing.status, ListingStatus::Active | ListingStatus::InAuction)
                                })
                        })
                    },
                    (None, Some(max)) => {
                        MARKETPLACE.with(|marketplace| {
                            marketplace.borrow()
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

#[derive(CandidType, Serialize, Deserialize)]
pub struct NFTSearchFilters {
    pub collection_name: Option<String>,
    pub min_price: Option<u64>,
    pub max_price: Option<u64>,
    pub creator: Option<Principal>,
    pub sort_by: Option<String>, // "price_asc", "price_desc", "newest", "oldest", "rarity"
}

#[query]
fn get_nft_collection_stats(collection_name: String) -> CollectionStats {
    let nfts: Vec<IPNft> = NFT_REGISTRY.with(|registry| {
        registry.borrow()
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
    let floor_price = MARKETPLACE.with(|marketplace| {
        marketplace.borrow()
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct CollectionStats {
    pub collection_name: String,
    pub total_supply: u32,
    pub unique_owners: u32,
    pub floor_price: Option<u64>,
    pub total_volume: u64,
    pub average_price: Option<u64>,
}

#[update]
fn increment_nft_view(nft_id: String) -> Result<u64> {
    NFT_REGISTRY.with(|registry| {
        let mut nfts = registry.borrow_mut();
        if let Some(mut nft) = nfts.get(&nft_id) {
            nft.view_count += 1;
            let new_count = nft.view_count;
            nfts.insert(nft_id, nft);
            Ok(new_count)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

#[update]
fn toggle_nft_favorite(nft_id: String) -> Result<u64> {
    let caller = ic_cdk::caller();
    
    // In a real implementation, you'd track individual user favorites
    // For simplicity, we're just incrementing/decrementing the total count
    NFT_REGISTRY.with(|registry| {
        let mut nfts = registry.borrow_mut();
        if let Some(mut nft) = nfts.get(&nft_id) {
            nft.favorite_count += 1; // In reality, check if user already favorited
            let new_count = nft.favorite_count;
            nfts.insert(nft_id, nft);
            Ok(new_count)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

#[update]
fn place_bid(listing_id: String, bid_amount: u64) -> Result<bool> {
    let caller = ic_cdk::caller();
    let now = time();
    
    MARKETPLACE.with(|marketplace| {
        let mut listings = marketplace.borrow_mut();
        if let Some(mut listing) = listings.get(&listing_id) {
            // Check if it's an auction
            if !matches!(listing.status, ListingStatus::InAuction) {
                return Err(IPMarketplaceError::InvalidInput);
            }
            
            if let Some(ref mut auction_data) = listing.auction_data {
                // Check if auction hasn't ended
                if now > auction_data.auction_end {
                    listing.status = ListingStatus::Expired;
                    listings.insert(listing_id, listing);
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
                
                listings.insert(listing_id, listing);
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
fn buy_nft(listing_id: String) -> Result<bool> {
    let caller = ic_cdk::caller();
    let now = time();
    
    MARKETPLACE.with(|marketplace| {
        let mut listings = marketplace.borrow_mut();
        if let Some(mut listing) = listings.get(&listing_id) {
            // Check if listing is active
            if !matches!(listing.status, ListingStatus::Active) {
                return Err(IPMarketplaceError::InvalidInput);
            }
            
            // Check if listing hasn't expired
            if let Some(expires_at) = listing.expires_at {
                if now > expires_at {
                    listing.status = ListingStatus::Expired;
                    listings.insert(listing_id, listing);
                    return Err(IPMarketplaceError::OperationFailed);
                }
            }
            
            // In a real implementation, you'd handle payment here
            // For now, we'll just simulate the transfer
            
            // Transfer NFT ownership
            let nft_id = listing.nft_id.clone();
            let seller = listing.seller;
            let price = listing.price;
            
            NFT_REGISTRY.with(|nft_registry| {
                let mut nfts = nft_registry.borrow_mut();
                if let Some(mut nft) = nfts.get(&nft_id) {
                    nft.owner = caller;
                    nft.transfer_history.push(TransferRecord {
                        from: seller,
                        to: caller,
                        timestamp: now,
                        transaction_hash: None,
                        price: Some(price),
                    });
                    nfts.insert(nft_id.clone(), nft);
                }
            });
            
            // Update user profiles
            USER_REGISTRY.with(|user_registry| {
                let mut users = user_registry.borrow_mut();
                
                // Update seller
                if let Some(mut seller_profile) = users.get(&seller) {
                    seller_profile.owned_nfts.retain(|id| id != &nft_id);
                    seller_profile.total_sales += price;
                    users.insert(seller, seller_profile);
                }
                
                // Update buyer
                if let Some(mut buyer_profile) = users.get(&caller) {
                    buyer_profile.owned_nfts.push(nft_id);
                    buyer_profile.total_purchases += price;
                    users.insert(caller, buyer_profile);
                }
            });
            
            // Mark listing as sold
            listing.status = ListingStatus::Sold;
            listings.insert(listing_id, listing);
            
            Ok(true)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

#[update]
fn cancel_listing(listing_id: String) -> Result<bool> {
    let caller = ic_cdk::caller();
    
    MARKETPLACE.with(|marketplace| {
        let mut listings = marketplace.borrow_mut();
        if let Some(mut listing) = listings.get(&listing_id) {
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
            listings.insert(listing_id, listing);
            Ok(true)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

#[query]
fn get_nft_history(nft_id: String) -> Result<Vec<TransferRecord>> {
    NFT_REGISTRY.with(|registry| {
        registry.borrow()
            .get(&nft_id)
            .map(|nft| nft.transfer_history.clone())
    }).ok_or(IPMarketplaceError::NotFound)
}

#[query]
fn get_marketplace_stats() -> MarketplaceStats {
    let mut total_listings = 0;
    let mut active_listings = 0;
    let mut total_volume = 0;
    let mut active_auctions = 0;
    
    MARKETPLACE.with(|marketplace| {
        for (_, listing) in marketplace.borrow().iter() {
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
    
    let total_nfts = NFT_REGISTRY.with(|registry| registry.borrow().len() as u32);
    let total_users = USER_REGISTRY.with(|registry| registry.borrow().len() as u32);
    
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct MarketplaceStats {
    pub total_nfts: u32,
    pub total_users: u32,
    pub total_listings: u32,
    pub active_listings: u32,
    pub active_auctions: u32,
    pub total_volume: u64,
    pub average_sale_price: Option<u64>,
}

// Batch operations for efficiency
#[query]
fn get_nfts_batch(nft_ids: Vec<String>) -> Vec<Option<IPNft>> {
    NFT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        nft_ids.into_iter()
            .map(|id| registry.get(&id))
            .collect()
    })
}

#[query]
fn get_listings_by_seller(seller: Principal) -> Vec<MarketplaceListing> {
    MARKETPLACE.with(|marketplace| {
        marketplace.borrow()
            .iter()
            .filter(|(_, listing)| listing.seller == seller)
            .map(|(_, listing)| listing.clone())
            .collect()
    })
}

// Admin functions (in a real implementation, these would have proper access control)
#[update]
fn verify_ip(ip_id: String, status: VerificationStatus) -> Result<bool> {
    // In production, this should check for admin privileges
    IP_REGISTRY.with(|registry| {
        let mut ips = registry.borrow_mut();
        if let Some(mut ip) = ips.get(&ip_id) {
            ip.verification_status = status;
            ips.insert(ip_id, ip);
            Ok(true)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}

#[update]
fn update_user_reputation(user: Principal, score_change: i32) -> Result<u32> {
    // In production, this should check for admin privileges
    USER_REGISTRY.with(|registry| {
        let mut users = registry.borrow_mut();
        if let Some(mut user_profile) = users.get(&user) {
            if score_change < 0 && (-score_change) as u32 > user_profile.reputation_score {
                user_profile.reputation_score = 0;
            } else {
                user_profile.reputation_score = (user_profile.reputation_score as i32 + score_change) as u32;
            }
            let new_score = user_profile.reputation_score;
            users.insert(user, user_profile);
            Ok(new_score)
        } else {
            Err(IPMarketplaceError::NotFound)
        }
    })
}