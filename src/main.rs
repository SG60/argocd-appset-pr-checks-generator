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
#[cfg(test)]
use mockall::automock;
use octocrab::params::repos::Commitish;
use serde::Deserialize;
use std::{collections::HashMap, fmt::Debug, sync::Arc};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{debug, info, instrument, trace};

#[derive(Clone, Debug)]
struct AppState {
    /// used by argocd to access this plugin
    plugin_access_token: String,
    /// An octocrab client to get stuff from GitHub
    github_data_getter: std::sync::Arc<dyn GetDataFromGitHub>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            github_data_getter: std::sync::Arc::new(octocrab::Octocrab::default()),
            plugin_access_token: String::default(),
        }
    }
}

#[instrument]
fn set_up_octocrab_client(
    github_app_id: String,
    github_app_private_key: String,
) -> octocrab::Octocrab {
    let octocrab = octocrab::OctocrabBuilder::new().app(
        github_app_id
            .parse::<u64>()
            .expect("should be valid u64 app ID")
            .into(),
        jsonwebtoken::EncodingKey::from_rsa_pem(github_app_private_key.as_bytes())
            .expect("should be a valid rsa pem value"),
    );

    octocrab
        .build()
        .expect("This should produce a valid octocrab client")
}

#[tokio::main]
async fn main() -> Result<()> {
    // initialise tracing
    opentelemetry_tracing_utils::set_up_logging().expect("tracing setup should work");

    let github_app_private_key = std::env::var("GITHUB_APP_PRIVATE_KEY")
        .context("Missing plugin access token (GITHUB_APP_PRIVATE_KEY)")?;
    let github_app_id =
        std::env::var("GITHUB_APP_ID").context("Missing plugin access token (GITHUB_APP_ID)")?;

    let plugin_access_token = std::env::var("ARGOCD_PLUGIN_TOKEN")
        .context("Missing plugin access token (ARGOCD_PLUGIN_TOKEN)")?;

    info!("starting up");

    let octocrab_client = Arc::new(set_up_octocrab_client(
        github_app_id,
        github_app_private_key,
    ));

    // let installations = octocrab_client.apps().installations().send().await?;
    // dbg!(installations);

    let app_state = AppState {
        plugin_access_token,
        github_data_getter: octocrab_client,
    };

    // build our application with a single route
    let app = app(app_state);

    let address_to_bind = "0.0.0.0:3000";
    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(address_to_bind)
        .await
        .unwrap();
    info!("Now listening on: {address_to_bind}");

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

    if format!("Bearer {}", state.plugin_access_token) == auth_header {
        info!("auth verification successful");
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::FORBIDDEN)
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

#[tracing::instrument(ret, err, skip(state, parts))]
async fn post_getparams_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    parts: axum::http::request::Parts,
    body: axum::extract::Json<JsonPayloadInputFromArgoCD>,
) -> Result<axum::Json<ResponseJsonPayload>, StatusCode> {
    debug!(
        "post value handler
Headers: {:?}
Parts: {:?}
Body: {:?}",
        &headers, &parts, &body
    );

    let parameters = &body.input.parameters;

    if parameters.required_checks.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let most_recent_successful_sha = state
        .github_data_getter
        .get_first_successful_check_runs_for_git_branch(
            parameters.repo_owner.clone(),
            parameters.repo_name.clone(),
            parameters.branch_name.clone(),
            parameters.required_checks.clone(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let result_vector = match most_recent_successful_sha {
        Some(sha_string) => vec![ResponseParameters {
            most_recent_successful_sha: sha_string,
        }],
        // just produce an empty vector if there is no valid commit
        None => Vec::new(),
    };

    let result_payload: ResponseJsonPayload = ResponseJsonPayload {
        output: ResponseJsonPayloadOutput {
            parameters: result_vector,
        },
    };

    Ok(axum::Json(result_payload))
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

trait GetSuccessfulCheckRuns: GetDataFromGitHub {
    /// Get completed checks for the specified git branch
    ///
    /// Returns the most recent commit SHA that has successfully completed
    /// the specified checks.
    ///
    /// # Errors
    ///
    /// This function will return an error if the Github API request fails
    #[instrument(ret, err(Debug))]
    async fn get_first_successful_check_runs_for_git_branch(
        &self,
        owner: String,
        repo: String,
        branch: String,
        check_names: Vec<String>,
    ) -> anyhow::Result<Option<String>> {
        let authenticated_octocrab_client = self
            .get_authenticated_repo_client(owner.clone(), repo.clone())
            .await?;

        let max_commits_to_try = 10;

        let mut successful_sha: Option<String> = None;
        let mut next_git_ref_to_check = "heads/".to_owned() + &branch;
        let mut commits_tried = 0;
        while successful_sha.is_none() && commits_tried < max_commits_to_try {
            let check_runs_for_current_ref_result = authenticated_octocrab_client
                .get_check_runs_for_git_ref(
                    owner.clone(),
                    repo.clone(),
                    next_git_ref_to_check.clone(),
                )
                .await
                .with_context(|| format!("Error getting check runs for {next_git_ref_to_check}"));

            trace!(
                checked_git_ref = next_git_ref_to_check,
                "Result of check run: {:?}",
                check_runs_for_current_ref_result
            );

            let check_runs_for_current_ref = check_runs_for_current_ref_result?;

            successful_sha = Some(check_runs_for_current_ref.head_sha);

            for i in &check_names {
                let conclusion = check_runs_for_current_ref
                    .check_runs
                    .get(i)
                    .map(|x| &x.conclusion);

                match conclusion {
                    Some(CheckConclusion::Success) => {}
                    None | Some(CheckConclusion::Failure) => {
                        successful_sha = None;
                        next_git_ref_to_check = check_runs_for_current_ref.parent_sha;
                        break;
                    }
                }
            }
            commits_tried += 1;
        }

        debug!(
            commits_tried,
            successful_sha, "Finished getting commit checks"
        );

        if let Some(expr) = successful_sha {
            Ok(Some(expr))
        } else {
            debug!("No valid commits within {max_commits_to_try} commits");
            Ok(None)
        }
    }
}

impl<T: ?Sized + GetDataFromGitHub> GetSuccessfulCheckRuns for T {}

#[cfg_attr(test, automock)]
#[async_trait]
trait GetDataFromGitHub: Send + Sync + Debug + 'static {
    /// Get runs for an individual ref
    async fn get_check_runs_for_git_ref(
        &self,
        owner: String,
        repo: String,
        git_ref: String,
    ) -> anyhow::Result<GetCheckRunsForGitRefResponse>;

    /// Get an app installation authenticated client for a repo
    async fn get_authenticated_repo_client(
        &self,
        owner: String,
        repo: String,
    ) -> anyhow::Result<Box<dyn GetDataFromGitHub>>;
}

#[derive(Debug, Clone)]
struct GetCheckRunsForGitRefResponse {
    check_runs: HashMap<String, CheckRun>,
    head_sha: String,
    parent_sha: String,
}
#[derive(Debug, Clone)]
struct CheckRun {
    conclusion: CheckConclusion,
}
#[derive(Debug, Clone)]
enum CheckConclusion {
    Success,
    Failure,
}

#[async_trait]
impl GetDataFromGitHub for octocrab::Octocrab {
    #[instrument(skip(self), err(Debug))]
    // Required for some reason due to the combination of async_trait macro and tracing
    // instrumentation macro
    #[allow(clippy::blocks_in_conditions)]
    async fn get_authenticated_repo_client(
        &self,
        owner: String,
        repo: String,
    ) -> anyhow::Result<Box<dyn GetDataFromGitHub>> {
        let app_repo_installation = self
            .apps()
            .get_repository_installation(owner.clone(), repo.clone())
            .await?;

        // repo authenticated octocrab client
        let authenticated_client = self.installation(app_repo_installation.id);

        Ok(Box::new(authenticated_client))
    }

    #[instrument(skip(self), err)]
    // Required for some reason due to the combination of async_trait macro and tracing
    // instrumentation macro
    #[allow(clippy::blocks_in_conditions)]
    async fn get_check_runs_for_git_ref(
        &self,
        owner: String,
        repo: String,
        git_ref: String,
    ) -> anyhow::Result<GetCheckRunsForGitRefResponse> {
        let commit = self
            .commits(owner.clone(), repo.clone())
            .get(git_ref.clone())
            .await?;

        let head_sha = &commit.sha;

        let commit_first_parent = &commit.parents[0];

        let checks = &self.checks(owner, repo);

        let checks = checks
            .list_check_runs_for_git_ref(Commitish(git_ref))
            .send()
            .await
            .context("Failed call to GitHub Checks API")?;

        trace!("Checks count: {:?}", checks.clone().total_count);

        //         todo!("Use the correct endpoint with query param to get only the stuff for one check name.
        // https://docs.rs/octocrab/latest/octocrab/index.html#http-api
        // https://docs.github.com/en/rest/checks/runs?apiVersion=2022-11-28#list-check-runs-for-a-git-reference");

        Ok(GetCheckRunsForGitRefResponse {
            head_sha: head_sha.to_owned(),
            parent_sha: commit_first_parent.sha.clone().expect("should be valid"),
            check_runs: checks
                .check_runs
                .iter()
                .map(|element| {
                    trace!("Check: {:?}", element);
                    (element.name.clone(), CheckRun::from(element.clone()))
                })
                .collect(),
        })
    }
}

impl From<octocrab::models::checks::CheckRun> for CheckRun {
    fn from(value: octocrab::models::checks::CheckRun) -> Self {
        Self {
            conclusion: (match value.conclusion.as_deref() {
                Some("success") => CheckConclusion::Success,
                _ => CheckConclusion::Failure,
            }),
        }
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
    #[allow(clippy::too_many_lines)]
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
            .expect_get_authenticated_repo_client()
            .once()
            .returning(|_, _| {
                let mut mock_github_authed_client = MockGetDataFromGitHub::new();
                mock_github_authed_client
                    .expect_get_check_runs_for_git_ref()
                    .times(1)
                    .with(
                        eq("a-github-user".to_owned()),
                        eq("asdfasdfadfs".to_owned()),
                        eq("heads/feature-branch-2".to_owned()),
                    )
                    .returning(|_, _, _| {
                        Ok(GetCheckRunsForGitRefResponse {
                            head_sha: "asdf".to_owned(),
                            parent_sha: successful_sha_for_test.to_owned(),
                            check_runs: HashMap::from([
                                (
                                    "test".to_owned(),
                                    CheckRun {
                                        conclusion: CheckConclusion::Failure,
                                    },
                                ),
                                (
                                    "build".to_owned(),
                                    CheckRun {
                                        conclusion: CheckConclusion::Success,
                                    },
                                ),
                            ]),
                        })
                    });
                mock_github_authed_client
                    .expect_get_check_runs_for_git_ref()
                    .times(1)
                    .with(
                        eq("a-github-user".to_owned()),
                        eq("asdfasdfadfs".to_owned()),
                        eq(successful_sha_for_test.to_owned()),
                    )
                    .returning(|_, _, _| {
                        Ok(GetCheckRunsForGitRefResponse {
                            head_sha: successful_sha_for_test.to_owned(),
                            parent_sha: "asdfasdfasdfadsf".to_owned(),
                            check_runs: HashMap::from([
                                (
                                    "test".to_owned(),
                                    CheckRun {
                                        conclusion: CheckConclusion::Success,
                                    },
                                ),
                                (
                                    "build".to_owned(),
                                    CheckRun {
                                        conclusion: CheckConclusion::Success,
                                    },
                                ),
                            ]),
                        })
                    });

                Ok(Box::new(mock_github_authed_client))
            });

        let app_state = AppState {
            plugin_access_token: argocd_plugin_token.to_string(),
            github_data_getter: Arc::new(mock_github_getter),
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
                    .header("Authorization", format!("Bearer {argocd_plugin_token}"))
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
