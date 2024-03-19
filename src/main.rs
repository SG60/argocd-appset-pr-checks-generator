use std::{default, fmt::Debug, sync::Arc};

use anyhow::{Context, Result};
use async_trait::async_trait;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::post,
    Router,
};
use hyper::body::Bytes;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
#[cfg(test)]
use mockall::automock;
use octocrab::params::repos::Commitish;
use opentelemetry_tracing_utils::{TracingLayer, TracingService};
use serde::Deserialize;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::trace::TraceLayer;
use tracing::{debug, info, instrument, trace};

#[derive(Clone, Debug)]
struct AppState {
    /// used by argocd to access this plugin
    plugin_access_token: String,
    client: TracingService<Client<HttpConnector, http_body_util::Full<Bytes>>>,
    /// An octocrab client to get stuff from GitHub
    github_data_getter: std::sync::Arc<dyn GetDataFromGitHub>,
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
            github_data_getter: std::sync::Arc::new(octocrab::Octocrab::default()),
            plugin_access_token: default::Default::default(),
            client: hyper_wrapped_client,
        }
    }
}

fn set_up_octocrab_client(github_app_token: String) -> octocrab::Octocrab {
    unimplemented!()
}

#[tokio::main]
async fn main() -> Result<()> {
    // initialise tracing
    opentelemetry_tracing_utils::set_up_logging().expect("tracing setup should work");

    let github_app_token = std::env::var("GITHUB_APP_TOKEN")
        .context("Missing plugin access token (GITHUB_APP_TOKEN)")?;

    let plugin_access_token = std::env::var("ARGOCD_PLUGIN_TOKEN")
        .context("Missing plugin access token (ARGOCD_PLUGIN_TOKEN)")?;

    info!("starting up");

    let octocrab_client = Arc::new(set_up_octocrab_client(github_app_token));

    let app_state = AppState {
        plugin_access_token,
        github_data_getter: octocrab_client,
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
        .route("/api/v1/getparams.execute", post(post_getparams_handler))
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    verify_bearer_auth_secret,
                ))
                // tower_http trace logging
                .layer(TraceLayer::new_for_http())
                .map_request(opentelemetry_tracing_utils::extract_trace_context),
        )
        .with_state(state)
}

#[tracing::instrument(err, skip_all)]
async fn verify_bearer_auth_secret(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if format!("Bearer {}", state.plugin_access_token) != auth_header {
        return Err(StatusCode::FORBIDDEN);
    } else {
        info!("auth verification successful");
        return Ok(next.run(request).await);
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ResponseJsonPayload {
    output: ResponseJsonPayloadOutput,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ResponseJsonPayloadOutput {
    parameters: Vec<ResponseParameters>,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ResponseParameters {
    most_recent_successful_sha: String,
}

#[tracing::instrument(ret, err, skip(state, parts, body))]
async fn post_getparams_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    parts: axum::http::request::Parts,
    body: axum::extract::Json<JsonPayloadInputFromArgoCD>,
    // body: String,
) -> Result<axum::Json<ResponseJsonPayload>, StatusCode> {
    debug!(
        "post value handler
Headers: {:?}
Parts: {:?}
Body: {:?}",
        &headers, &parts, &body
    );

    let parameters = &body.input.parameters;

    let mut vec_of_check_runs: Vec<CheckRun> = vec![];

    for required_check in &parameters.required_checks {
        let mut vec_of_runs_for_check = state
            .github_data_getter
            .get_check_runs_for_git_branch(
                parameters.repo_owner.to_owned(),
                parameters.repo_name.to_owned(),
                parameters.branch_name.to_owned(),
                required_check.to_owned(),
            )
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        vec_of_check_runs.append(&mut vec_of_runs_for_check);
    }

    debug!("Result of call: {:?}", vec_of_check_runs);

    let successful_runs = vec_of_check_runs
        .iter()
        .filter_map(|el| match el.conclusion {
            CheckConclusion::Success => Some(el.head_sha.clone()),
            _ => None,
        });

    todo!("need to implement getting the most recent check");

    trace!(
        "Successful Runs: {:?}",
        successful_runs.clone().collect::<Vec<_>>()
    );

    let response_parameters = ResponseParameters {
        most_recent_successful_sha: "asdf".to_owned(),
    };

    let result: ResponseJsonPayload = ResponseJsonPayload {
        output: ResponseJsonPayloadOutput {
            parameters: vec![response_parameters],
        },
    };

    Ok(axum::Json(result))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct JsonPayloadInputFromArgoCD {
    // application_set_name: String,
    input: JsonArgoCDInput,
}
#[derive(Deserialize, Debug)]
struct JsonArgoCDInput {
    parameters: ArgoCDParameters,
}
#[derive(Deserialize, Debug)]
struct ArgoCDParameters {
    branch_name: String,
    repo_owner: String,
    repo_name: String,
    required_checks: Vec<String>,
}

#[cfg_attr(test, automock)]
#[async_trait]
trait GetDataFromGitHub: Send + Sync + Debug + 'static {
    /// Get completed checks for the specified git branch and requested check name
    ///
    /// # Errors
    ///
    /// This function will return an error if the Github API request fails
    async fn get_check_runs_for_git_branch(
        &self,
        owner: String,
        repo: String,
        branch: String,
        check_name: String,
    ) -> anyhow::Result<Vec<CheckRun>>;
}

#[derive(Debug, Clone)]
struct CheckRun {
    conclusion: CheckConclusion,
    head_sha: String,
}
#[derive(Debug, Clone)]
enum CheckConclusion {
    Success,
    Failure,
}
#[async_trait]
impl GetDataFromGitHub for octocrab::Octocrab {
    #[instrument(ret, skip(self))]
    async fn get_check_runs_for_git_branch(
        &self,
        owner: String,
        repo: String,
        branch: String,
        check_name: String,
    ) -> anyhow::Result<Vec<CheckRun>> {
        let checks = &self.checks(owner, repo);

        let checks = checks
            .list_check_runs_for_git_ref(Commitish("heads/".to_owned() + &branch))
            .send()
            .await
            .context("Failed call to GitHub Checks API")?;

        trace!("Checks: {:?}", checks.clone(),);

        Ok(checks
            .check_runs
            .iter()
            .map(|element| CheckRun {
                head_sha: element.head_sha.clone(),
                conclusion: (match element.conclusion.as_deref() {
                    Some("Success") => CheckConclusion::Success,
                    _ => CheckConclusion::Failure,
                }),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use axum::{body::Body, http::Request};
    use indoc::indoc;
    use mockall::predicate::eq;
    use opentelemetry_tracing_utils::LoggingSetupBuilder;
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;

    fn test_setup() {
        let _ = LoggingSetupBuilder {
            use_test_writer: true,
            pretty_logs: true,
            otlp_output_enabled: false,
        }
        .build();
    }

    #[tokio::test]
    async fn successful_getparams_request() {
        test_setup();

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

        let successful_sha_for_test = "asdfasdf33333";

        let mut mock_github_getter = MockGetDataFromGitHub::new();
        mock_github_getter
            .expect_get_check_runs_for_git_branch()
            .times(1)
            .with(
                eq("a-github-user".to_owned()),
                eq("asdfasdfadfs".to_owned()),
                eq("feature-branch-2".to_owned()),
                eq("build".to_owned()),
            )
            .returning(|_, _, _, _| {
                Ok(vec![CheckRun {
                    head_sha: successful_sha_for_test.to_owned(),
                    conclusion: CheckConclusion::Success,
                }])
            });

        let app_state = AppState {
            plugin_access_token: argocd_plugin_token.to_string(),
            github_data_getter: Arc::new(mock_github_getter),
            ..Default::default()
        };

        debug!(?app_state, "Server App State");

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
                    .header("Content-Type", "application/json")
                    .body(request_body)
                    .unwrap(),
            )
            .await
            .unwrap();

        // Response should be equivalent to this
        let expected_response_body = json!({
            "output": {
                "parameters": [{"most_recent_successful_sha": successful_sha_for_test}]
            }
        });

        let (parts, body) = response.into_parts();
        let body_string: String = String::from_utf8(
            axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        trace!("response parts: {:?}", &parts);

        let body_json = serde_json::Value::from_str(&body_string).unwrap();
        debug!("Received JSON: {}", body_json);

        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(body_json, expected_response_body);
    }

    #[tokio::test]
    async fn unauthenticated() {
        test_setup();

        // `Router` implements `tower::Service<Request<Body>>` so we can
        // call it like any tower service, no need to run an HTTP server.
        let response = app(AppState {
            plugin_access_token: "very-secret-auth-token".to_string(),
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
