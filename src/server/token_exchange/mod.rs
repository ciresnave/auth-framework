//! Token Exchange Implementation Module
//!
//! This module contains token exchange functionality including:
//! - Token exchange common utilities
//! - Token exchange factory
//! - Advanced token exchange
//! - Token introspection

pub mod advanced_token_exchange;
pub mod core;
pub mod token_exchange_common;
pub mod token_exchange_factory;

// Re-export commonly used types
pub use advanced_token_exchange::{
    AdvancedTokenExchangeConfig, AdvancedTokenExchangeManager, AdvancedTokenExchangeRequest,
    TokenExchangePolicy as AdvancedTokenExchangePolicy,
};
pub use core::{
    TokenExchangeManager, TokenExchangePolicy, TokenExchangeRequest, TokenExchangeResponse,
};
pub use token_exchange_common::*;
pub use token_exchange_factory::*;
