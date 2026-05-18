//! Rust-side condition evaluation. Sync, fast, no I/O (Convention 5).
//!
//! Used by:
//!   * `player_sync` worker — evaluate a single (viewer, channel) pair when a
//!     webhook or verify event fires.
//!   * `services::sync::evaluate_player_for_link` — produce add/remove
//!     decisions for a single role link.
//!
//! The bulk per-role-link path uses [services::rule_sql::build_rule_where]
//! instead — it pushes the same predicates down into Postgres.

use serde_json::Value;

use crate::models::condition::{Condition, ConditionOperator, ConditionTarget};
use crate::models::facts::Facts;
use crate::models::rule::RuleTree;

/// Evaluate the rule tree against a viewer's facts.
///
/// - `grant_on_any_relation = true` short-circuits to `true`.
/// - Otherwise an empty `groups` slice returns `false` (Convention 42).
/// - Otherwise: ANY group matches (OR) and each group requires ALL of its
///   conditions to match (AND). Empty groups are FALSE (defensive; the
///   validator already rejects them at save).
pub fn evaluate(tree: &RuleTree, facts: &Facts) -> bool {
    if tree.grant_on_any_relation {
        return true;
    }
    if tree.groups.is_empty() {
        return false;
    }
    tree.groups
        .iter()
        .any(|g| !g.conditions.is_empty() && g.conditions.iter().all(|c| evaluate_single(c, facts)))
}

fn evaluate_single(c: &Condition, f: &Facts) -> bool {
    use ConditionTarget::*;

    // Pull the actual value as the appropriate Rust type. We branch on target
    // because each target has a fixed natural type — we don't unify everything
    // into serde_json::Value, that'd be slower and lose precision.
    match c.target {
        // -- booleans --
        IsFollower => bool_match(c, f.is_follower),
        IsSubscriber => bool_match(c, f.is_subscriber),
        IsGiftRecipient => bool_match(c, f.sub_is_gift),
        IsVip => bool_match(c, f.is_vip),
        IsModerator => bool_match(c, f.is_moderator),
        IsOg => bool_match(c, f.is_og),

        // -- integers --
        FollowAgeDays => int_match(c, days_since(f.followed_at)),
        SubMonthsCumulative => int_match(c, Some(f.sub_months_cumulative)),
        SubStreakMonths => int_match(c, Some(f.sub_streak_months)),
        GiftedSubsGiven => int_match(c, Some(f.gifted_subs_given)),
        KicksDonatedToChannel => int_match(c, Some(f.kicks_donated)),
        ChatMessages30d => int_match(c, Some(f.chat_messages_30d)),
        AccountAgeDays => int_match(c, days_since(f.kick_created_at)),

        // -- strings (nullable) --
        CountryCode => string_match(c, f.country_code.as_deref()),
        Username => string_match(c, Some(f.username.as_str())),
    }
}

fn bool_match(c: &Condition, actual: bool) -> bool {
    if !matches!(c.operator, ConditionOperator::Eq) {
        return false;
    }
    c.value.as_bool().map(|v| v == actual).unwrap_or(false)
}

fn int_match(c: &Condition, actual: Option<i64>) -> bool {
    let Some(a) = actual else {
        return false; // missing data ⇒ fail-closed
    };
    let v = c.value.as_i64();
    match c.operator {
        ConditionOperator::Eq => v.map(|n| a == n).unwrap_or(false),
        ConditionOperator::Neq => v.map(|n| a != n).unwrap_or(false),
        ConditionOperator::Gt => v.map(|n| a > n).unwrap_or(false),
        ConditionOperator::Gte => v.map(|n| a >= n).unwrap_or(false),
        ConditionOperator::Lt => v.map(|n| a < n).unwrap_or(false),
        ConditionOperator::Lte => v.map(|n| a <= n).unwrap_or(false),
        ConditionOperator::Between => {
            let lo = v;
            let hi = c.value_end.as_ref().and_then(|x| x.as_i64());
            match (lo, hi) {
                (Some(lo), Some(hi)) => a >= lo && a <= hi,
                _ => false,
            }
        }
        _ => false,
    }
}

fn string_match(c: &Condition, actual: Option<&str>) -> bool {
    let Some(a) = actual else {
        // For `neq` against missing, treat as match (mirrors FRR pattern —
        // "anyone who DIDN'T set country=US" works against unset country).
        return matches!(c.operator, ConditionOperator::Neq);
    };
    let v = c.value.as_str();
    match c.operator {
        ConditionOperator::Eq => v.map(|s| a == s).unwrap_or(false),
        ConditionOperator::Neq => v.map(|s| a != s).unwrap_or(false),
        ConditionOperator::Contains => v.map(|s| a.contains(s)).unwrap_or(false),
        ConditionOperator::Regex => {
            let Some(pattern) = v else { return false };
            // `regex` crate has linear-time matching (no catastrophic
            // backtracking). Bound compiled size + DFA cache so a malicious
            // pattern can't OOM us — same caps as the save-time validator.
            let Ok(re) = regex::RegexBuilder::new(pattern)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
            else {
                return false;
            };
            re.is_match(a)
        }
        ConditionOperator::In => list_contains(&c.value, a),
        ConditionOperator::NotIn => !list_contains(&c.value, a),
        _ => false,
    }
}

fn list_contains(value: &Value, needle: &str) -> bool {
    value
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).any(|s| s == needle))
        .unwrap_or(false)
}

fn days_since(ts: Option<chrono::DateTime<chrono::Utc>>) -> Option<i64> {
    ts.map(|t| (chrono::Utc::now() - t).num_days())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::condition::ConditionTarget as T;
    use crate::models::rule::{ConditionGroup, RuleTree};
    use chrono::Duration;
    use serde_json::json;

    fn c(target: T, op: ConditionOperator, value: Value) -> Condition {
        Condition {
            target,
            operator: op,
            value,
            value_end: None,
        }
    }

    fn one_group(conds: Vec<Condition>) -> RuleTree {
        RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup { conditions: conds }],
        }
    }

    fn or_groups(g: Vec<Vec<Condition>>) -> RuleTree {
        RuleTree {
            grant_on_any_relation: false,
            groups: g
                .into_iter()
                .map(|cs| ConditionGroup { conditions: cs })
                .collect(),
        }
    }

    fn facts() -> Facts {
        Facts::default()
    }

    // ---------- Convention 42 ----------

    #[test]
    fn convention_42_no_groups_no_grant_means_nobody() {
        let t = RuleTree::default();
        assert!(!evaluate(&t, &facts()));
    }

    #[test]
    fn grant_on_any_short_circuits_true() {
        let t = RuleTree {
            grant_on_any_relation: true,
            groups: vec![],
        };
        assert!(evaluate(&t, &facts()));
    }

    #[test]
    fn empty_group_is_false_defensive() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup { conditions: vec![] }],
        };
        assert!(!evaluate(&t, &facts()));
    }

    // ---------- AND within group ----------

    #[test]
    fn and_all_conditions_required() {
        let t = one_group(vec![
            c(T::IsSubscriber, ConditionOperator::Eq, json!(true)),
            c(T::SubMonthsCumulative, ConditionOperator::Gte, json!(3)),
        ]);
        let mut f = facts();
        f.is_subscriber = true;
        f.sub_months_cumulative = 5;
        assert!(evaluate(&t, &f));

        f.sub_months_cumulative = 2;
        assert!(!evaluate(&t, &f));
    }

    // ---------- OR across groups ----------

    #[test]
    fn or_any_group_satisfies() {
        // (subscriber AND >=3mo) OR (VIP)
        let t = or_groups(vec![
            vec![
                c(T::IsSubscriber, ConditionOperator::Eq, json!(true)),
                c(T::SubMonthsCumulative, ConditionOperator::Gte, json!(3)),
            ],
            vec![c(T::IsVip, ConditionOperator::Eq, json!(true))],
        ]);

        let mut f = facts();
        // sub path matches
        f.is_subscriber = true;
        f.sub_months_cumulative = 5;
        assert!(evaluate(&t, &f));

        // sub path fails; vip path matches
        f.is_subscriber = false;
        f.is_vip = true;
        assert!(evaluate(&t, &f));

        // both fail
        f.is_vip = false;
        assert!(!evaluate(&t, &f));
    }

    // ---------- numeric ----------

    #[test]
    fn between_inclusive() {
        let mut cond = c(T::SubMonthsCumulative, ConditionOperator::Between, json!(3));
        cond.value_end = Some(json!(12));
        let t = one_group(vec![cond]);

        let mut f = facts();
        f.sub_months_cumulative = 3;
        assert!(evaluate(&t, &f));
        f.sub_months_cumulative = 12;
        assert!(evaluate(&t, &f));
        f.sub_months_cumulative = 13;
        assert!(!evaluate(&t, &f));
        f.sub_months_cumulative = 2;
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn follow_age_days_from_timestamp() {
        let t = one_group(vec![c(T::FollowAgeDays, ConditionOperator::Gte, json!(30))]);
        let mut f = facts();
        f.followed_at = Some(chrono::Utc::now() - Duration::days(45));
        assert!(evaluate(&t, &f));
        f.followed_at = Some(chrono::Utc::now() - Duration::days(15));
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn missing_int_fails_closed() {
        // FollowAgeDays with no followed_at ⇒ missing data ⇒ false
        let t = one_group(vec![c(T::FollowAgeDays, ConditionOperator::Gte, json!(0))]);
        let f = facts(); // followed_at = None
        assert!(!evaluate(&t, &f));
    }

    // ---------- string ----------

    #[test]
    fn regex_against_username() {
        let t = one_group(vec![c(
            T::Username,
            ConditionOperator::Regex,
            json!(r"^streamer_\w+$"),
        )]);
        let mut f = facts();
        f.username = "streamer_jack".into();
        assert!(evaluate(&t, &f));
        f.username = "jack".into();
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn bad_regex_returns_false_not_panic() {
        let t = one_group(vec![c(T::Username, ConditionOperator::Regex, json!("(("))]);
        let mut f = facts();
        f.username = "anything".into();
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn country_in_list() {
        let t = one_group(vec![c(
            T::CountryCode,
            ConditionOperator::In,
            json!(["US", "CA", "GB"]),
        )]);
        let mut f = facts();
        f.country_code = Some("CA".into());
        assert!(evaluate(&t, &f));
        f.country_code = Some("FR".into());
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn not_in_inverse() {
        let t = one_group(vec![c(
            T::CountryCode,
            ConditionOperator::NotIn,
            json!(["US"]),
        )]);
        let mut f = facts();
        f.country_code = Some("CA".into());
        assert!(evaluate(&t, &f));
        f.country_code = Some("US".into());
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn null_country_neq_passes() {
        // Mirrors FRR convention: neq against an unset string is satisfied
        // if expected is non-empty — admins use this for "anyone NOT in X".
        let t = one_group(vec![c(T::CountryCode, ConditionOperator::Neq, json!("US"))]);
        let f = facts();
        assert!(evaluate(&t, &f));
    }

    // ---------- combined realistic rule ----------

    #[test]
    fn realistic_tier_rule() {
        // "@Loyal" role: (subscriber AND ≥6mo) OR (VIP) OR (gift recipient AND streak ≥3)
        let t = or_groups(vec![
            vec![
                c(T::IsSubscriber, ConditionOperator::Eq, json!(true)),
                c(T::SubMonthsCumulative, ConditionOperator::Gte, json!(6)),
            ],
            vec![c(T::IsVip, ConditionOperator::Eq, json!(true))],
            vec![
                c(T::IsGiftRecipient, ConditionOperator::Eq, json!(true)),
                c(T::SubStreakMonths, ConditionOperator::Gte, json!(3)),
            ],
        ]);

        // Long-time sub
        let mut f = facts();
        f.is_subscriber = true;
        f.sub_months_cumulative = 12;
        assert!(evaluate(&t, &f));

        // Just a VIP, never subbed
        let mut f = facts();
        f.is_vip = true;
        assert!(evaluate(&t, &f));

        // Gift sub on month 3
        let mut f = facts();
        f.sub_is_gift = true;
        f.sub_streak_months = 3;
        assert!(evaluate(&t, &f));

        // Random follower — no path matches
        let mut f = facts();
        f.is_follower = true;
        assert!(!evaluate(&t, &f));
    }
}
