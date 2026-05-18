//! Condition target / operator types used in the rule tree.
//!
//! - `ConditionTarget` names a fact we can read from a (viewer, channel) pair.
//! - `ConditionOperator` names a comparison.
//! - Validity of an (target, operator) combination is enforced at save time
//!   in [services::rule_validator] using each target's `kind()`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What kind of data this target produces. Drives which operators are valid
/// and how the rule_validator coerces literal values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Bool,
    Int,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionTarget {
    // -- viewer × channel facts (read from channel_relations) --
    IsFollower,
    FollowAgeDays,
    IsSubscriber,
    SubMonthsCumulative,
    SubStreakMonths,
    IsGiftRecipient,
    GiftedSubsGiven,
    IsVip,
    IsModerator,
    KicksDonatedToChannel,
    ChatMessages30d,

    // -- viewer account facts (read from kick_users) --
    IsOg,
    AccountAgeDays,
    CountryCode,
    Username,
}

impl ConditionTarget {
    pub fn kind(self) -> TargetKind {
        use ConditionTarget::*;
        match self {
            IsFollower | IsSubscriber | IsGiftRecipient | IsVip | IsModerator | IsOg => {
                TargetKind::Bool
            }
            FollowAgeDays
            | SubMonthsCumulative
            | SubStreakMonths
            | GiftedSubsGiven
            | KicksDonatedToChannel
            | ChatMessages30d
            | AccountAgeDays => TargetKind::Int,
            CountryCode | Username => TargetKind::String,
        }
    }

    pub fn as_str(self) -> &'static str {
        use ConditionTarget::*;
        match self {
            IsFollower => "is_follower",
            FollowAgeDays => "follow_age_days",
            IsSubscriber => "is_subscriber",
            SubMonthsCumulative => "sub_months_cumulative",
            SubStreakMonths => "sub_streak_months",
            IsGiftRecipient => "is_gift_recipient",
            GiftedSubsGiven => "gifted_subs_given",
            IsVip => "is_vip",
            IsModerator => "is_moderator",
            KicksDonatedToChannel => "kicks_donated_to_channel",
            ChatMessages30d => "chat_messages_30d",
            IsOg => "is_og",
            AccountAgeDays => "account_age_days",
            CountryCode => "country_code",
            Username => "username",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        use ConditionTarget::*;
        Some(match s {
            "is_follower" => IsFollower,
            "follow_age_days" => FollowAgeDays,
            "is_subscriber" => IsSubscriber,
            "sub_months_cumulative" => SubMonthsCumulative,
            "sub_streak_months" => SubStreakMonths,
            "is_gift_recipient" => IsGiftRecipient,
            "gifted_subs_given" => GiftedSubsGiven,
            "is_vip" => IsVip,
            "is_moderator" => IsModerator,
            "kicks_donated_to_channel" => KicksDonatedToChannel,
            "chat_messages_30d" => ChatMessages30d,
            "is_og" => IsOg,
            "account_age_days" => AccountAgeDays,
            "country_code" => CountryCode,
            "username" => Username,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Between,
    Contains,
    Regex,
    In,
    NotIn,
}

impl ConditionOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Neq => "neq",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Between => "between",
            Self::Contains => "contains",
            Self::Regex => "regex",
            Self::In => "in",
            Self::NotIn => "not_in",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        Some(match s {
            "eq" => Self::Eq,
            "neq" => Self::Neq,
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            "between" => Self::Between,
            "contains" => Self::Contains,
            "regex" => Self::Regex,
            "in" => Self::In,
            "not_in" => Self::NotIn,
            _ => return None,
        })
    }

    /// Operators that produce a meaningful predicate on each target kind.
    /// Save-time validation rejects mismatches.
    pub fn valid_for(self, kind: TargetKind) -> bool {
        use ConditionOperator::*;
        match kind {
            TargetKind::Bool => matches!(self, Eq),
            TargetKind::Int => matches!(self, Eq | Neq | Gt | Gte | Lt | Lte | Between),
            TargetKind::String => matches!(self, Eq | Neq | Contains | Regex | In | NotIn),
        }
    }
}

/// A single condition row inside an AND-group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub target: ConditionTarget,
    pub operator: ConditionOperator,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_end: Option<Value>,
}
