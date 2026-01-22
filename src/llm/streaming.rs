//! Streaming response handling for LLM requests
//!
//! Provides utilities for handling Server-Sent Events (SSE) streaming
//! responses from LLM providers.

use bytes::{Bytes, BytesMut};
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

use crate::llm::config::{StreamChunk, TokenUsage};

/// Streaming response aggregator
/// Collects streaming chunks and tracks token usage
pub struct StreamAggregator {
    /// Accumulated content
    content: String,
    /// Total chunks received
    chunk_count: usize,
    /// Estimated input tokens
    input_tokens: u32,
    /// Output tokens from stream
    output_tokens: u32,
    /// Model name
    model: Option<String>,
    /// Response ID
    id: Option<String>,
    /// Finish reason
    finish_reason: Option<String>,
    /// Whether the stream is complete
    complete: bool,
}

impl StreamAggregator {
    /// Create a new stream aggregator
    pub fn new() -> Self {
        Self {
            content: String::new(),
            chunk_count: 0,
            input_tokens: 0,
            output_tokens: 0,
            model: None,
            id: None,
            finish_reason: None,
            complete: false,
        }
    }

    /// Create with known input tokens
    pub fn with_input_tokens(input_tokens: u32) -> Self {
        Self {
            content: String::new(),
            chunk_count: 0,
            input_tokens,
            output_tokens: 0,
            model: None,
            id: None,
            finish_reason: None,
            complete: false,
        }
    }

    /// Process a streaming chunk
    pub fn process_chunk(&mut self, chunk: &StreamChunk) {
        self.chunk_count += 1;

        // Capture metadata from first chunk
        if self.id.is_none() {
            self.id = Some(chunk.id.clone());
        }
        if self.model.is_none() {
            self.model = Some(chunk.model.clone());
        }

        // Extract content from choices
        for choice in &chunk.choices {
            if let Some(delta) = &choice.delta {
                if let Some(content) = &delta.content {
                    if let crate::llm::config::MessageContent::Text(text) = content {
                        self.content.push_str(text);
                        // Rough estimation: 4 chars = 1 token
                        self.output_tokens += (text.len() / 4).max(1) as u32;
                    }
                }
            }

            if let Some(reason) = &choice.finish_reason {
                self.finish_reason = Some(reason.clone());
                self.complete = true;
            }
        }
    }

    /// Mark the stream as complete
    pub fn complete(&mut self) {
        self.complete = true;
    }

    /// Check if the stream is complete
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Get the accumulated content
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Get the chunk count
    pub fn chunk_count(&self) -> usize {
        self.chunk_count
    }

    /// Get estimated token usage
    pub fn token_usage(&self) -> TokenUsage {
        TokenUsage {
            prompt_tokens: self.input_tokens,
            completion_tokens: self.output_tokens,
            total_tokens: self.input_tokens + self.output_tokens,
            cached_tokens: None,
        }
    }

    /// Get the finish reason
    pub fn finish_reason(&self) -> Option<&str> {
        self.finish_reason.as_deref()
    }

    /// Get the model name
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// Get the response ID
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

impl Default for StreamAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// SSE line parser for streaming responses
pub struct SseParser {
    buffer: BytesMut,
    event_type: Option<String>,
}

impl SseParser {
    /// Create a new SSE parser
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
            event_type: None,
        }
    }

    /// Parse incoming bytes and extract complete SSE events
    pub fn parse(&mut self, data: &[u8]) -> Vec<SseEvent> {
        self.buffer.extend_from_slice(data);
        let mut events = Vec::new();

        loop {
            // Find line ending
            let line_end = self.buffer.iter().position(|&b| b == b'\n');
            if line_end.is_none() {
                break;
            }

            let line_end = line_end.unwrap();
            let line = self.buffer.split_to(line_end + 1);
            let line = std::str::from_utf8(&line)
                .unwrap_or("")
                .trim_end_matches(|c| c == '\r' || c == '\n');

            if line.is_empty() {
                // Empty line - event boundary
                continue;
            }

            if line.starts_with("event:") {
                self.event_type = Some(line[6..].trim().to_string());
            } else if line.starts_with("data:") {
                let data = line[5..].trim();
                events.push(SseEvent {
                    event_type: self.event_type.take(),
                    data: data.to_string(),
                });
            } else if line.starts_with(":") {
                // Comment, ignore
            }
        }

        events
    }

    /// Reset the parser state
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.event_type = None;
    }
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new()
    }
}

/// SSE event
#[derive(Debug, Clone)]
pub struct SseEvent {
    /// Event type (optional)
    pub event_type: Option<String>,
    /// Event data
    pub data: String,
}

impl SseEvent {
    /// Check if this is the done marker
    pub fn is_done(&self) -> bool {
        self.data == "[DONE]"
    }

    /// Parse the data as JSON
    pub fn parse_json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(&self.data)
    }
}

/// Stream transformer that adds token tracking
pub struct TokenTrackingStream<S> {
    #[allow(dead_code)]
    inner: S,
    aggregator: StreamAggregator,
    on_complete: Option<Box<dyn FnOnce(TokenUsage) + Send>>,
}

impl<S> TokenTrackingStream<S> {
    /// Create a new token tracking stream
    pub fn new(inner: S, input_tokens: u32) -> Self {
        Self {
            inner,
            aggregator: StreamAggregator::with_input_tokens(input_tokens),
            on_complete: None,
        }
    }

    /// Set a callback for when the stream completes
    pub fn on_complete<F>(mut self, f: F) -> Self
    where
        F: FnOnce(TokenUsage) + Send + 'static,
    {
        self.on_complete = Some(Box::new(f));
        self
    }

    /// Get the aggregator
    pub fn aggregator(&self) -> &StreamAggregator {
        &self.aggregator
    }
}

/// Streaming body wrapper for hyper responses
pub struct StreamingBody {
    rx: mpsc::Receiver<Bytes>,
}

impl StreamingBody {
    /// Create a new streaming body
    pub fn new(rx: mpsc::Receiver<Bytes>) -> Self {
        Self { rx }
    }

    /// Create a channel pair for streaming
    pub fn channel(buffer: usize) -> (mpsc::Sender<Bytes>, Self) {
        let (tx, rx) = mpsc::channel(buffer);
        (tx, Self::new(rx))
    }
}

impl Stream for StreamingBody {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.rx).poll_recv(cx) {
            Poll::Ready(Some(bytes)) => Poll::Ready(Some(Ok(bytes))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Format SSE data line
pub fn format_sse_data(data: &str) -> String {
    format!("data: {}\n\n", data)
}

/// Format SSE event with type
pub fn format_sse_event(event_type: &str, data: &str) -> String {
    format!("event: {}\ndata: {}\n\n", event_type, data)
}

/// Format SSE done marker
pub fn format_sse_done() -> &'static str {
    "data: [DONE]\n\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_parser() {
        let mut parser = SseParser::new();

        let data = b"data: {\"id\": \"1\"}\n\ndata: {\"id\": \"2\"}\n\n";
        let events = parser.parse(data);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "{\"id\": \"1\"}");
        assert_eq!(events[1].data, "{\"id\": \"2\"}");
    }

    #[test]
    fn test_sse_parser_with_event_type() {
        let mut parser = SseParser::new();

        let data = b"event: message\ndata: hello\n\n";
        let events = parser.parse(data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, Some("message".to_string()));
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn test_stream_aggregator() {
        let mut aggregator = StreamAggregator::with_input_tokens(100);

        let chunk = StreamChunk {
            id: "test-1".to_string(),
            object: "chat.completion.chunk".to_string(),
            created: 0,
            model: "gpt-4".to_string(),
            choices: vec![crate::llm::config::ResponseChoice {
                index: 0,
                message: None,
                text: None,
                finish_reason: None,
                logprobs: None,
                delta: Some(crate::llm::config::ChatMessage {
                    role: "assistant".to_string(),
                    content: Some(crate::llm::config::MessageContent::Text("Hello".to_string())),
                    name: None,
                    function_call: None,
                    tool_calls: None,
                    tool_call_id: None,
                }),
            }],
        };

        aggregator.process_chunk(&chunk);

        assert_eq!(aggregator.content(), "Hello");
        assert_eq!(aggregator.chunk_count(), 1);
        assert!(!aggregator.is_complete());
    }

    #[test]
    fn test_sse_formatting() {
        let data = format_sse_data("{\"test\": true}");
        assert_eq!(data, "data: {\"test\": true}\n\n");

        let event = format_sse_event("message", "hello");
        assert_eq!(event, "event: message\ndata: hello\n\n");
    }
}
