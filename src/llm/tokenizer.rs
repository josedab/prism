//! Token counting utilities for LLM requests
//!
//! Provides estimation of token counts for various tokenizers.
//! For production use, consider using tiktoken-rs for accurate counts.

use crate::llm::config::{ChatMessage, LlmRequest, MessageContent, TokenizerType};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Token counter trait
pub trait TokenCounter: Send + Sync {
    /// Count tokens in a string
    fn count_tokens(&self, text: &str) -> usize;

    /// Count tokens in a chat message
    fn count_message_tokens(&self, message: &ChatMessage) -> usize;

    /// Count tokens in an LLM request
    fn count_request_tokens(&self, request: &LlmRequest) -> usize;

    /// Get the tokenizer type
    fn tokenizer_type(&self) -> TokenizerType;
}

/// Simple word-based token estimator
/// Uses approximately 4 characters per token (OpenAI average)
pub struct SimpleTokenCounter;

impl TokenCounter for SimpleTokenCounter {
    fn count_tokens(&self, text: &str) -> usize {
        // Rough estimation: ~4 characters per token for English text
        // This is based on OpenAI's observation that 1 token ≈ 4 characters
        let char_count = text.chars().count();
        (char_count + 3) / 4
    }

    fn count_message_tokens(&self, message: &ChatMessage) -> usize {
        let mut tokens = 0;

        // Role token overhead (approximately 1 token)
        tokens += 1;

        // Content tokens
        if let Some(content) = &message.content {
            tokens += match content {
                MessageContent::Text(text) => self.count_tokens(text),
                MessageContent::Parts(parts) => {
                    parts.iter().map(|p| {
                        match p {
                            crate::llm::config::ContentPart::Text { text } => self.count_tokens(text),
                            crate::llm::config::ContentPart::ImageUrl { .. } => 85, // Base tokens for an image
                        }
                    }).sum()
                }
            };
        }

        // Name tokens
        if let Some(name) = &message.name {
            tokens += self.count_tokens(name) + 1;
        }

        // Function call tokens
        if let Some(fc) = &message.function_call {
            tokens += self.count_tokens(&fc.to_string());
        }

        // Tool calls tokens
        if let Some(tools) = &message.tool_calls {
            for tool in tools {
                tokens += self.count_tokens(&tool.to_string());
            }
        }

        // Message formatting overhead (~3 tokens per message)
        tokens + 3
    }

    fn count_request_tokens(&self, request: &LlmRequest) -> usize {
        let mut tokens = 0;

        // Count message tokens
        for message in &request.messages {
            tokens += self.count_message_tokens(message);
        }

        // Count prompt tokens if present (legacy completion API)
        if let Some(prompt) = &request.prompt {
            tokens += self.count_tokens(prompt);
        }

        // Function definitions overhead
        if let Some(functions) = &request.functions {
            for func in functions {
                tokens += self.count_tokens(&func.to_string());
            }
        }

        // Tool definitions overhead
        if let Some(tools) = &request.tools {
            for tool in tools {
                tokens += self.count_tokens(&tool.to_string());
            }
        }

        // Request overhead (~3 tokens)
        tokens + 3
    }

    fn tokenizer_type(&self) -> TokenizerType {
        TokenizerType::Simple
    }
}

/// Character-based token estimator (more conservative)
/// Uses approximately 3.5 characters per token
pub struct CharBasedTokenCounter;

impl TokenCounter for CharBasedTokenCounter {
    fn count_tokens(&self, text: &str) -> usize {
        // More conservative: ~3.5 characters per token
        let char_count = text.chars().count();
        ((char_count as f64 / 3.5).ceil()) as usize
    }

    fn count_message_tokens(&self, message: &ChatMessage) -> usize {
        let mut tokens = 0;

        tokens += 1; // Role

        if let Some(content) = &message.content {
            tokens += match content {
                MessageContent::Text(text) => self.count_tokens(text),
                MessageContent::Parts(parts) => {
                    parts.iter().map(|p| {
                        match p {
                            crate::llm::config::ContentPart::Text { text } => self.count_tokens(text),
                            crate::llm::config::ContentPart::ImageUrl { image_url } => {
                                // Image token estimation based on detail level
                                match image_url.detail.as_deref() {
                                    Some("high") => 765,
                                    Some("low") => 85,
                                    _ => 170, // auto/medium
                                }
                            }
                        }
                    }).sum()
                }
            };
        }

        if let Some(name) = &message.name {
            tokens += self.count_tokens(name) + 1;
        }

        if let Some(fc) = &message.function_call {
            tokens += self.count_tokens(&fc.to_string());
        }

        if let Some(tools) = &message.tool_calls {
            for tool in tools {
                tokens += self.count_tokens(&tool.to_string());
            }
        }

        tokens + 4 // Message overhead
    }

    fn count_request_tokens(&self, request: &LlmRequest) -> usize {
        let mut tokens = 0;

        for message in &request.messages {
            tokens += self.count_message_tokens(message);
        }

        if let Some(prompt) = &request.prompt {
            tokens += self.count_tokens(prompt);
        }

        if let Some(functions) = &request.functions {
            for func in functions {
                tokens += self.count_tokens(&func.to_string());
            }
        }

        if let Some(tools) = &request.tools {
            for tool in tools {
                tokens += self.count_tokens(&tool.to_string());
            }
        }

        tokens + 3
    }

    fn tokenizer_type(&self) -> TokenizerType {
        TokenizerType::CharBased
    }
}

/// CL100k tokenizer estimation (GPT-4, GPT-3.5-turbo)
/// More accurate estimation based on known patterns
pub struct Cl100kTokenCounter;

impl Cl100kTokenCounter {
    /// Estimate tokens using cl100k_base patterns
    fn estimate_tokens(text: &str) -> usize {
        let mut tokens = 0;
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            // Check for common multi-character tokens
            let _remaining = &chars[i..];

            // Whitespace handling
            if chars[i].is_whitespace() {
                // Multiple spaces often merge
                let mut space_count = 0;
                while i < chars.len() && chars[i].is_whitespace() {
                    space_count += 1;
                    i += 1;
                }
                // Roughly 1 token per 2-3 spaces
                tokens += (space_count + 1) / 2;
                continue;
            }

            // Numbers often get their own tokens
            if chars[i].is_ascii_digit() {
                let mut num_len = 0;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    num_len += 1;
                    i += 1;
                }
                // 1-3 digit numbers are usually 1 token
                tokens += (num_len + 2) / 3;
                continue;
            }

            // Common words (simplified - real tokenizer has vocabulary)
            if chars[i].is_alphabetic() {
                let mut word_len = 0;
                while i < chars.len() && chars[i].is_alphanumeric() {
                    word_len += 1;
                    i += 1;
                }
                // Average English word is ~4-5 characters, usually 1-2 tokens
                tokens += (word_len + 3) / 4;
                continue;
            }

            // Punctuation and special characters
            tokens += 1;
            i += 1;
        }

        tokens.max(1)
    }
}

impl TokenCounter for Cl100kTokenCounter {
    fn count_tokens(&self, text: &str) -> usize {
        Self::estimate_tokens(text)
    }

    fn count_message_tokens(&self, message: &ChatMessage) -> usize {
        let mut tokens = 0;

        // OpenAI chat format: <|start|>{role}<|end|>
        tokens += 4; // Format tokens

        if let Some(content) = &message.content {
            tokens += match content {
                MessageContent::Text(text) => self.count_tokens(text),
                MessageContent::Parts(parts) => {
                    parts.iter().map(|p| {
                        match p {
                            crate::llm::config::ContentPart::Text { text } => self.count_tokens(text),
                            crate::llm::config::ContentPart::ImageUrl { image_url } => {
                                match image_url.detail.as_deref() {
                                    Some("high") => 765,
                                    Some("low") => 85,
                                    _ => 170,
                                }
                            }
                        }
                    }).sum()
                }
            };
        }

        if let Some(name) = &message.name {
            tokens += self.count_tokens(name) + 1;
        }

        if let Some(fc) = &message.function_call {
            // Function calls have specific formatting
            tokens += self.count_tokens(&fc.to_string()) + 2;
        }

        if let Some(tools) = &message.tool_calls {
            for tool in tools {
                tokens += self.count_tokens(&tool.to_string()) + 2;
            }
        }

        tokens
    }

    fn count_request_tokens(&self, request: &LlmRequest) -> usize {
        let mut tokens = 0;

        for message in &request.messages {
            tokens += self.count_message_tokens(message);
        }

        if let Some(prompt) = &request.prompt {
            tokens += self.count_tokens(prompt);
        }

        // Function definitions
        if let Some(functions) = &request.functions {
            for func in functions {
                let func_str = func.to_string();
                tokens += self.count_tokens(&func_str);
                tokens += 10; // Function definition overhead
            }
        }

        // Tool definitions (similar to functions)
        if let Some(tools) = &request.tools {
            for tool in tools {
                let tool_str = tool.to_string();
                tokens += self.count_tokens(&tool_str);
                tokens += 10; // Tool definition overhead
            }
        }

        // Request overhead
        tokens + 3
    }

    fn tokenizer_type(&self) -> TokenizerType {
        TokenizerType::Cl100kBase
    }
}

/// Claude tokenizer estimation
pub struct ClaudeTokenCounter;

impl TokenCounter for ClaudeTokenCounter {
    fn count_tokens(&self, text: &str) -> usize {
        // Claude's tokenizer is similar to GPT but slightly different
        // Generally produces slightly more tokens for the same text
        let char_count = text.chars().count();
        ((char_count as f64 / 3.8).ceil()) as usize
    }

    fn count_message_tokens(&self, message: &ChatMessage) -> usize {
        let mut tokens = 0;

        // Claude uses different message format
        tokens += 3; // Role and format tokens

        if let Some(content) = &message.content {
            tokens += match content {
                MessageContent::Text(text) => self.count_tokens(text),
                MessageContent::Parts(parts) => {
                    parts.iter().map(|p| {
                        match p {
                            crate::llm::config::ContentPart::Text { text } => self.count_tokens(text),
                            crate::llm::config::ContentPart::ImageUrl { .. } => 170, // Claude image tokens
                        }
                    }).sum()
                }
            };
        }

        if let Some(name) = &message.name {
            tokens += self.count_tokens(name) + 1;
        }

        if let Some(tools) = &message.tool_calls {
            for tool in tools {
                tokens += self.count_tokens(&tool.to_string()) + 3;
            }
        }

        tokens
    }

    fn count_request_tokens(&self, request: &LlmRequest) -> usize {
        let mut tokens = 0;

        for message in &request.messages {
            tokens += self.count_message_tokens(message);
        }

        if let Some(prompt) = &request.prompt {
            tokens += self.count_tokens(prompt);
        }

        if let Some(tools) = &request.tools {
            for tool in tools {
                tokens += self.count_tokens(&tool.to_string()) + 5;
            }
        }

        tokens + 5 // Claude request overhead
    }

    fn tokenizer_type(&self) -> TokenizerType {
        TokenizerType::Claude
    }
}

/// Factory for creating token counters
pub fn create_token_counter(tokenizer_type: &TokenizerType) -> Arc<dyn TokenCounter> {
    match tokenizer_type {
        TokenizerType::Cl100kBase => Arc::new(Cl100kTokenCounter),
        TokenizerType::P50kBase => Arc::new(SimpleTokenCounter), // Simplified
        TokenizerType::Claude => Arc::new(ClaudeTokenCounter),
        TokenizerType::Simple => Arc::new(SimpleTokenCounter),
        TokenizerType::CharBased => Arc::new(CharBasedTokenCounter),
    }
}

/// Token counter registry
pub struct TokenCounterRegistry {
    counters: RwLock<HashMap<TokenizerType, Arc<dyn TokenCounter>>>,
    default_counter: Arc<dyn TokenCounter>,
}

impl TokenCounterRegistry {
    /// Create a new registry with default counters
    pub fn new() -> Self {
        let mut counters = HashMap::new();
        counters.insert(TokenizerType::Cl100kBase, create_token_counter(&TokenizerType::Cl100kBase));
        counters.insert(TokenizerType::Claude, create_token_counter(&TokenizerType::Claude));
        counters.insert(TokenizerType::Simple, create_token_counter(&TokenizerType::Simple));
        counters.insert(TokenizerType::CharBased, create_token_counter(&TokenizerType::CharBased));

        Self {
            counters: RwLock::new(counters),
            default_counter: create_token_counter(&TokenizerType::Cl100kBase),
        }
    }

    /// Get a token counter for the given type
    pub fn get(&self, tokenizer_type: &TokenizerType) -> Arc<dyn TokenCounter> {
        let counters = self.counters.read();
        counters.get(tokenizer_type)
            .cloned()
            .unwrap_or_else(|| self.default_counter.clone())
    }

    /// Get the default counter
    pub fn default(&self) -> Arc<dyn TokenCounter> {
        self.default_counter.clone()
    }
}

impl Default for TokenCounterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_token_counter() {
        let counter = SimpleTokenCounter;

        // Test basic text
        let text = "Hello, world!";
        let tokens = counter.count_tokens(text);
        assert!(tokens > 0);
        assert!(tokens < 10);

        // Test empty text
        let empty = "";
        assert_eq!(counter.count_tokens(empty), 0);
    }

    #[test]
    fn test_cl100k_token_counter() {
        let counter = Cl100kTokenCounter;

        // Test various text types
        let text = "The quick brown fox jumps over the lazy dog.";
        let tokens = counter.count_tokens(text);
        assert!(tokens > 5);
        // Estimation is approximate - real cl100k produces ~10, our estimate may vary
        assert!(tokens < 30, "tokens: {}", tokens);

        // Test numbers
        let numbers = "12345";
        let num_tokens = counter.count_tokens(numbers);
        assert!(num_tokens >= 1);
        assert!(num_tokens <= 3);
    }

    #[test]
    fn test_chat_message_tokens() {
        let counter = SimpleTokenCounter;

        let message = ChatMessage {
            role: "user".to_string(),
            content: Some(MessageContent::Text("Hello, how are you?".to_string())),
            name: None,
            function_call: None,
            tool_calls: None,
            tool_call_id: None,
        };

        let tokens = counter.count_message_tokens(&message);
        assert!(tokens > 0);
    }

    #[test]
    fn test_request_tokens() {
        let counter = Cl100kTokenCounter;

        let request = LlmRequest {
            model: "gpt-4".to_string(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: Some(MessageContent::Text("You are a helpful assistant.".to_string())),
                    name: None,
                    function_call: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: Some(MessageContent::Text("Hello!".to_string())),
                    name: None,
                    function_call: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
            ],
            prompt: None,
            max_tokens: Some(100),
            temperature: Some(0.7),
            top_p: None,
            n: None,
            stream: false,
            stop: None,
            presence_penalty: None,
            frequency_penalty: None,
            user: None,
            functions: None,
            tools: None,
            extra: HashMap::new(),
        };

        let tokens = counter.count_request_tokens(&request);
        assert!(tokens > 0);
    }
}
