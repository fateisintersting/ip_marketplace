use sha2::{Digest, Sha256};
use crate::types::{NFTAttribute, AttributeValue};

// Utility functions
pub fn generate_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn format_timestamp(timestamp: u64) -> String {
    // Convert nanoseconds to a readable format
    // This is a simplified version - in production, use proper date formatting
    format!("{}", timestamp / 1_000_000_000) // Convert to seconds
}

pub fn validate_image_url(url: &str) -> bool {
    // Basic validation for image URLs
    url.starts_with("http://") || url.starts_with("https://") || url.starts_with("ipfs://")
}

pub fn calculate_rarity_score(attributes: &[NFTAttribute]) -> f64 {
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
