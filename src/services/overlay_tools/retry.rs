//! Double-spend retry utility for overlay operations.
//!
//! Translates the TS SDK withDoubleSpendRetry.ts. Retries an operation
//! up to a configurable number of times when a double-spend error is detected.

use std::future::Future;

use crate::services::ServicesError;

/// Default maximum retry attempts for double-spend resolution.
const MAX_DOUBLE_SPEND_RETRIES: u32 = 5;

/// Executes an operation with automatic retry logic for double-spend errors.
///
/// When the operation fails with an error whose message contains "double spend"
/// or "competing transaction", it is retried up to `max_retries` times.
/// Non-double-spend errors are immediately propagated.
///
/// No backoff is applied between retries, matching the TS SDK behavior.
pub async fn with_double_spend_retry<F, Fut, T>(
    f: F,
    max_retries: Option<u32>,
) -> Result<T, ServicesError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, ServicesError>>,
{
    let max = max_retries.unwrap_or(MAX_DOUBLE_SPEND_RETRIES);
    let mut attempts = 0u32;

    loop {
        attempts += 1;
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempts >= max || !is_double_spend_error(&e) {
                    return Err(e);
                }
                // Retry without backoff.
                continue;
            }
        }
    }
}

/// Check if an error indicates a double-spend condition.
fn is_double_spend_error(err: &ServicesError) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("double spend") || msg.contains("competing transaction")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_succeeds_on_first_try() {
        let result = with_double_spend_retry(|| async { Ok::<_, ServicesError>(42) }, None).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retries_on_double_spend() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = with_double_spend_retry(
            move || {
                let c = counter_clone.clone();
                async move {
                    let attempt = c.fetch_add(1, Ordering::SeqCst);
                    if attempt < 2 {
                        Err(ServicesError::Overlay("double spend detected".to_string()))
                    } else {
                        Ok(42)
                    }
                }
            },
            Some(5),
        )
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_fails_after_max_retries() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = with_double_spend_retry(
            move || {
                let c = counter_clone.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err::<i32, _>(ServicesError::Overlay("double spend error".to_string()))
                }
            },
            Some(3),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_non_double_spend_error_not_retried() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = with_double_spend_retry(
            move || {
                let c = counter_clone.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err::<i32, _>(ServicesError::Overlay("network timeout".to_string()))
                }
            },
            Some(5),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_competing_transaction_is_retried() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = with_double_spend_retry(
            move || {
                let c = counter_clone.clone();
                async move {
                    let attempt = c.fetch_add(1, Ordering::SeqCst);
                    if attempt == 0 {
                        Err(ServicesError::Overlay(
                            "competing transaction found".to_string(),
                        ))
                    } else {
                        Ok("ok")
                    }
                }
            },
            Some(5),
        )
        .await;

        assert_eq!(result.unwrap(), "ok");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
}
