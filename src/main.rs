use std::default;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::post,
    Router,
};
use futures::StreamExt;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use opentelemetry_tracing_utils::{OpenTelemetrySpanExt, TracingLayer, TracingService};
use ring::hmac;
use serde_json::json;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_http::trace::TraceLayer;
use tracing::{debug, debug_span, error, info, trace, Instrument};

#[derive(Clone, Debug)]
struct AppState {
    /// used by argocd to access this plugin
    plugin_access_token: String,
    github_app_token: String,
    client: TracingService<Client<HttpConnector, http_body_util::Full<Bytes>>>,
}

impl Default for AppState {
    fn default() -> Self {
        let hyper_client =
            Client::builder(TokioExecutor::new()).build_http::<http_body_util::Full<Bytes>>();

        let tower_service_stack = ServiceBuilder::new()
            .layer(TracingLayer)
            .service(hyper_client);

        let hyper_wrapped_client = futures::executor::block_on(tower_service_stack.clone().ready())
            .expect("should be valid")
            .to_owned();

        Self {
            plugin_access_token: default::Default::default(),
            github_app_token: default::Default::default(),
            client: hyper_wrapped_client,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // initialise tracing
    opentelemetry_tracing_utils::set_up_logging().expect("tracing setup should work");

    // TODO: Get the auth token from a file or environment variable
    let plugin_access_token = std::env::var("ARGOCD_PLUGIN_TOKEN")
        .context("Missing plugin access token (ARGOCD_PLUGIN_TOKEN)")?;

    info!("starting up");

    let app_state = AppState {
        plugin_access_token,
        ..Default::default()
    };

    // build our application with a single route
    let app = app(app_state);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    opentelemetry_tracing_utils::shutdown_tracer_provider();

    Ok(())
}

#[tracing::instrument(ret)]
fn app(state: AppState) -> Router {
    info!("creating router");
    Router::new()
        .route("/api/webhook", post(post_webhook_handler))
        .layer(
            ServiceBuilder::new()
                // tower_http trace logging
                .layer(TraceLayer::new_for_http())
                .map_request(opentelemetry_tracing_utils::extract_trace_context),
        )
        .with_state(state)
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ResponseJsonPayload {
    message: String,
    responses: Vec<IndividualWebhookResponse>,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct IndividualWebhookResponse {
    source: String,
    status: u16,
    body: serde_json::Value,
}

#[tracing::instrument(ret, err, skip(state, parts, body))]
async fn post_webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    parts: axum::http::request::Parts,
    body: Body,
    // body: String,
) -> Result<axum::Json<ResponseJsonPayload>, StatusCode> {
    debug!("{:?}", &headers);

    debug!(
        "current trace context: {:#?}",
        tracing::Span::current().context()
    );

    Err(StatusCode::BAD_REQUEST)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axum::{body::Body, http::Request};
    use indoc::indoc;
    use serde_json::json;
    use tower::ServiceExt;
    use wiremock::{
        matchers::{self, method},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;

    #[tokio::test]
    async fn successful_getparams_request() {
        let _ = opentelemetry_tracing_utils::set_up_logging();

        let argocd_plugin_token = "very-secret-auth-token";

        // input from the argocd application set
        let body_content = indoc! { r#"
            {
                "applicationSetName": "appset-12345",
                "input": {
                    "parameters": {
                        "branch_name": "feature-branch-2",
                        "repo_owner": "a-github-user",
                        "repo_name": "asdfasdfadfs",
                        "required_checks": ["build", "test"]
                    }
                }
            }
            "#};
        let request_body = Body::from(body_content);

        // Start a background mock HTTP server on a random local port
        let mock_server = MockServer::start().await;

        // Arrange the behaviour of the MockServer adding a Mock
        // This should mock the github api response?!
        Mock::given(method("POST"))
            .and(matchers::path("/webhook"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "stuff stuff stuff",
                "webhook_data_1": "webhook info info info"
            })))
            .expect(1)
            // We assign a name to the mock - it will be shown in error messages
            // if our expectation is not verified!
            .named("webhook 1")
            // Mounting the mock on the mock server - it's now effective!
            .mount(&mock_server)
            .await;

        let app_state = AppState {
            ..Default::default()
        };

        debug!(body_content, "Request Details. Body: {}", body_content);

        let app = app(app_state);
        // `Router` implements `tower::Service<Request<Body>>` so we can
        // call it like any tower service, no need to run an HTTP server.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/getparams.execute")
                    .method("POST")
                    .header("Authorization", format!("Bearer {}", argocd_plugin_token))
                    .body(request_body)
                    .unwrap(),
            )
            .await
            .unwrap();

        // Response should be equivalent to this
        let expected_response = indoc! {r#"
            {
                "output": {
                    "parameters": [
                        {
                            "most_recent_successful_sha": "asdf34easdf"
                        }
                    ]
                }
            }
        "#};

        let (parts, body) = response.into_parts();
        let body_string: String = String::from_utf8(
            axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        debug!("{:?}", &parts);
        let body_json = serde_json::Value::from_str(&body_string);
        debug!("{:?}", &body_string);
        debug!("Expected JSON response: {}", &expected_response);

        assert_eq!(parts.status, StatusCode::OK);
        assert!(body_string.contains("forwarded"));
        assert!(body_string.contains("webhook info info info"));
    }

    #[tokio::test]
    async fn unauthenticated() {
        let _ = opentelemetry_tracing_utils::set_up_logging();

        let argocd_plugin_token = "very-secret-auth-token";

        // `Router` implements `tower::Service<Request<Body>>` so we can
        // call it like any tower service, no need to run an HTTP server.
        let response = app(AppState {
            plugin_access_token: argocd_plugin_token.to_string(),
            ..Default::default()
        })
        .oneshot(
            Request::builder()
                .uri("/api/v1/getparams.execute")
                .method("POST")
                .header("Authorization", "Bearer not-the-correct-token")
                .body(Body::from("Hello, World!"))
                .unwrap(),
        )
        .await
        .unwrap();

        let response_status = response.status();

        debug!(?response_status, "Response Received");

        // the request should be forbidden due to incorrect token
        assert_eq!(response_status, StatusCode::FORBIDDEN);
    }
}
