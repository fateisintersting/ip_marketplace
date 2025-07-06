use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use std::borrow::Cow;

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

// Request types
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
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub social_links: Option<Vec<SocialLink>>,
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

#[derive(CandidType, Serialize, Deserialize)]
pub struct NFTSearchFilters {
    pub collection_name: Option<String>,
    pub min_price: Option<u64>,
    pub max_price: Option<u64>,
    pub creator: Option<Principal>,
    pub sort_by: Option<String>, // "price_asc", "price_desc", "newest", "oldest", "rarity"
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

pub type Result<T> = std::result::Result<T, IPMarketplaceError>;

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
