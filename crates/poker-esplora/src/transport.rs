use std::time::Duration;

use crate::EsploraError;

/// Default end-to-end HTTP timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) trait HttpTransport: Send + Sync {
    fn get(&self, url: &str, maximum: usize) -> Result<Vec<u8>, EsploraError>;
    fn post_text(&self, url: &str, body: &str, maximum: usize) -> Result<Vec<u8>, EsploraError>;
}

#[derive(Debug)]
pub(crate) struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    pub(crate) fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .timeout_global(Some(DEFAULT_TIMEOUT))
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .build();
        Self {
            agent: config.into(),
        }
    }
}

impl HttpTransport for UreqTransport {
    fn get(&self, url: &str, maximum: usize) -> Result<Vec<u8>, EsploraError> {
        let maximum_u64 =
            u64::try_from(maximum).map_err(|_| EsploraError::ResponseTooLarge { maximum })?;
        let mut response = self
            .agent
            .get(url)
            .call()
            .map_err(|error| map_request_error(&error))?;
        response
            .body_mut()
            .with_config()
            .limit(maximum_u64)
            .read_to_vec()
            .map_err(|_| EsploraError::ResponseTooLarge { maximum })
    }

    fn post_text(&self, url: &str, body: &str, maximum: usize) -> Result<Vec<u8>, EsploraError> {
        let maximum_u64 =
            u64::try_from(maximum).map_err(|_| EsploraError::ResponseTooLarge { maximum })?;
        let mut response = self
            .agent
            .post(url)
            .header("content-type", "text/plain")
            .send(body)
            .map_err(|error| map_request_error(&error))?;
        response
            .body_mut()
            .with_config()
            .limit(maximum_u64)
            .read_to_vec()
            .map_err(|_| EsploraError::ResponseTooLarge { maximum })
    }
}

fn map_request_error(error: &ureq::Error) -> EsploraError {
    match error {
        ureq::Error::StatusCode(404) => EsploraError::NotFound,
        _ => EsploraError::Transport,
    }
}
