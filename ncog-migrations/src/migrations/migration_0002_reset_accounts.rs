use super::{JONS_ACCOUNT_ID, JONS_ITCHIO_ID};
use sqlx_simple_migrator::Migration;

pub fn migration() -> Migration {
    Migration::new("0002")
        .with_up(&format!(
            "UPDATE itchio_profiles SET account_id = {} WHERE id = {}",
            JONS_ACCOUNT_ID, JONS_ITCHIO_ID
        ))
        .with_up("DELETE FROM installations")
        .with_up("DELETE FROM oauth_tokens")
        .with_up("DELETE FROM accounts WHERE id > 1")
        .with_up("INSERT INTO accounts DEFAULT VALUES")
}
