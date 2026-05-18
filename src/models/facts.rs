//! Plain-data view of (viewer × channel) facts needed for condition
//! evaluation. Constructed by sync workers from `channel_relations`,
//! `kick_users`, and `broadcasters` joined on (kick_channel_id, kick_user_id).
//!
//! Kept POD (no methods, no I/O) so [services::condition_eval::evaluate]
//! stays sync and fast (Convention 5).

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Default)]
pub struct Facts {
    // -- per-viewer-per-channel (channel_relations) --
    pub is_follower: bool,
    pub followed_at: Option<DateTime<Utc>>,
    pub is_subscriber: bool,
    pub sub_months_cumulative: i64,
    pub sub_streak_months: i64,
    pub sub_is_gift: bool,
    pub gifted_subs_given: i64,
    pub is_vip: bool,
    pub is_moderator: bool,
    pub kicks_donated: i64,
    pub chat_messages_30d: i64,

    // -- per-viewer (kick_users) --
    pub is_og: bool,
    pub kick_created_at: Option<DateTime<Utc>>,
    pub country_code: Option<String>,
    pub username: String,
}
