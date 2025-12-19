//! Middleware chain implementation

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::error::Result;
use async_trait::async_trait;
use std::sync::Arc;

/// A chain of middleware that processes requests in order
pub struct MiddlewareChain {
    middlewares: Vec<Arc<dyn Middleware>>,
    handler: Arc<dyn Handler>,
}

/// The final handler that processes the request after all middleware
#[async_trait]
pub trait Handler: Send + Sync {
    /// Handle the request
    async fn handle(&self, request: HttpRequest, ctx: RequestContext) -> Result<HttpResponse>;
}

impl MiddlewareChain {
    /// Create a new middleware chain
    pub fn new(middlewares: Vec<Arc<dyn Middleware>>, handler: Arc<dyn Handler>) -> Self {
        Self {
            middlewares,
            handler,
        }
    }

    /// Execute the middleware chain
    pub async fn execute(&self, request: HttpRequest, ctx: RequestContext) -> Result<HttpResponse> {
        if self.middlewares.is_empty() {
            return self.handler.handle(request, ctx).await;
        }

        let executor = ChainExecutor {
            middlewares: &self.middlewares,
            handler: &self.handler,
            current: 0,
        };

        executor.run(request, ctx).await
    }
}

/// Internal executor for the middleware chain
struct ChainExecutor<'a> {
    middlewares: &'a [Arc<dyn Middleware>],
    handler: &'a Arc<dyn Handler>,
    current: usize,
}

#[async_trait]
impl<'a> Next for ChainExecutor<'a> {
    async fn run(&self, request: HttpRequest, ctx: RequestContext) -> Result<HttpResponse> {
        if self.current >= self.middlewares.len() {
            // All middleware processed, call the final handler
            return self.handler.handle(request, ctx).await;
        }

        let middleware = &self.middlewares[self.current];
        let next = ChainExecutor {
            middlewares: self.middlewares,
            handler: self.handler,
            current: self.current + 1,
        };

        middleware.process(request, ctx, &next).await
    }
}

/// A simple handler that wraps a function
pub struct FnHandler<F>
where
    F: Fn(HttpRequest, RequestContext) -> futures::future::BoxFuture<'static, Result<HttpResponse>>
        + Send
        + Sync,
{
    f: F,
}

impl<F> FnHandler<F>
where
    F: Fn(HttpRequest, RequestContext) -> futures::future::BoxFuture<'static, Result<HttpResponse>>
        + Send
        + Sync,
{
    /// Create a new function handler
    pub fn new(f: F) -> Self {
        Self { f }
    }
}

#[async_trait]
impl<F> Handler for FnHandler<F>
where
    F: Fn(HttpRequest, RequestContext) -> futures::future::BoxFuture<'static, Result<HttpResponse>>
        + Send
        + Sync,
{
    async fn handle(&self, request: HttpRequest, ctx: RequestContext) -> Result<HttpResponse> {
        (self.f)(request, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::Response;
    use http_body_util::Full;

    struct TestMiddleware {
        name: &'static str,
        add_header: String,
    }

    #[async_trait]
    impl Middleware for TestMiddleware {
        async fn process(
            &self,
            request: HttpRequest,
            ctx: RequestContext,
            next: &dyn Next,
        ) -> Result<HttpResponse> {
            let header_name = self.add_header.clone();
            let mut response = next.run(request, ctx).await?;
            response.headers_mut().insert(
                http::header::HeaderName::try_from(header_name).unwrap(),
                "true".parse().unwrap(),
            );
            Ok(response)
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    struct TestHandler;

    #[async_trait]
    impl Handler for TestHandler {
        async fn handle(
            &self,
            _request: HttpRequest,
            _ctx: RequestContext,
        ) -> Result<HttpResponse> {
            Ok(Response::builder()
                .status(200)
                .body(Full::new(Bytes::from("OK")))
                .unwrap())
        }
    }
}
