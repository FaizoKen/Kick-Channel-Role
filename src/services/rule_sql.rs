//! SQL WHERE-clause builder for bulk per-role-link sync.
//!
//! Pushes the same DNF semantics as [services::condition_eval::evaluate] down
//! into Postgres so `sync_for_role_link` filters server-side instead of
//! loading every viewer's facts into memory (Convention 6 / 8).
//!
//! The clause references two aliases the caller must provide:
//!   * `ku`  — kick_users
//!   * `cr`  — channel_relations (LEFT JOINed; columns may be NULL)
//!
//! NULL-handling is chosen to match the Rust evaluator's fail-closed
//! behavior: a viewer with no `channel_relations` row (COALESCEd to
//! false/0) is treated identically to one whose facts are all default.

use crate::models::condition::{Condition, ConditionOperator, ConditionTarget};
use crate::models::rule::RuleTree;

#[derive(Debug, Clone)]
pub enum Bind {
    Bool(bool),
    Int(i64),
    Text(String),
    TextArray(Vec<String>),
}

/// Returns ("clause", binds). Binds use parameter indices starting at
/// `bind_offset + 1`. Convention 42: `grant_on_any_relation = false` AND no
/// groups ⇒ "FALSE" (match nobody). `grant_on_any_relation = true` ⇒ "TRUE".
pub fn build_rule_where(tree: &RuleTree, bind_offset: usize) -> (String, Vec<Bind>) {
    if tree.grant_on_any_relation {
        return ("TRUE".to_string(), vec![]);
    }
    if tree.groups.is_empty() {
        return ("FALSE".to_string(), vec![]);
    }

    let mut binds: Vec<Bind> = Vec::new();
    let mut group_clauses: Vec<String> = Vec::new();

    for group in &tree.groups {
        if group.conditions.is_empty() {
            group_clauses.push("FALSE".to_string());
            continue;
        }
        let mut cond_clauses: Vec<String> = Vec::new();
        for c in &group.conditions {
            cond_clauses.push(build_condition(c, bind_offset, &mut binds));
        }
        group_clauses.push(format!("({})", cond_clauses.join(" AND ")));
    }

    (format!("({})", group_clauses.join(" OR ")), binds)
}

/// SQL expression for a target. Returns the expression text typed
/// appropriately: bools COALESCE to false, ints to 0, nullable strings and
/// the age expressions stay NULL-able (so comparisons fail closed).
fn target_expr(target: ConditionTarget) -> &'static str {
    use ConditionTarget::*;
    match target {
        IsFollower => "COALESCE(cr.is_follower, false)",
        FollowAgeDays => "FLOOR(EXTRACT(EPOCH FROM (now() - cr.followed_at)) / 86400)",
        IsSubscriber => "COALESCE(cr.is_subscriber, false)",
        SubMonthsCumulative => "COALESCE(cr.sub_months_cumulative, 0)",
        SubStreakMonths => "COALESCE(cr.sub_streak_months, 0)",
        IsGiftRecipient => "COALESCE(cr.sub_is_gift, false)",
        GiftedSubsGiven => "COALESCE(cr.gifted_subs_given, 0)",
        IsVip => "COALESCE(cr.is_vip, false)",
        IsModerator => "COALESCE(cr.is_moderator, false)",
        KicksDonatedToChannel => "COALESCE(cr.kicks_donated, 0)",
        ChatMessages30d => "COALESCE(cr.chat_messages_30d, 0)",
        IsOg => "COALESCE(ku.is_og, false)",
        AccountAgeDays => "FLOOR(EXTRACT(EPOCH FROM (now() - ku.kick_created_at)) / 86400)",
        CountryCode => "ku.country_code",
        Username => "ku.kick_username",
    }
}

fn build_condition(c: &Condition, bind_offset: usize, binds: &mut Vec<Bind>) -> String {
    use ConditionOperator::*;
    let expr = target_expr(c.target);

    let next = |binds: &Vec<Bind>| bind_offset + binds.len() + 1;

    match c.operator {
        Eq => {
            // Bool target → bind bool; everything else binds as the value's
            // natural type. We branch on the JSON value shape.
            if let Some(b) = c.value.as_bool() {
                let i = next(binds);
                binds.push(Bind::Bool(b));
                format!("{expr} = ${i}")
            } else if let Some(n) = c.value.as_i64() {
                let i = next(binds);
                binds.push(Bind::Int(n));
                format!("{expr} = ${i}")
            } else {
                let i = next(binds);
                binds.push(Bind::Text(c.value.as_str().unwrap_or("").to_string()));
                format!("{expr} = ${i}")
            }
        }
        Neq => {
            if let Some(n) = c.value.as_i64() {
                let i = next(binds);
                binds.push(Bind::Int(n));
                // Plain <> so NULL int (missing age) is NOT matched —
                // matches the Rust evaluator's fail-closed int behavior.
                format!("{expr} <> ${i}")
            } else {
                let i = next(binds);
                binds.push(Bind::Text(c.value.as_str().unwrap_or("").to_string()));
                // IS DISTINCT FROM so NULL string (unset country) DOES match
                // `neq` — matches the Rust evaluator's string behavior.
                format!("{expr} IS DISTINCT FROM ${i}")
            }
        }
        Gt | Gte | Lt | Lte => {
            let n = c.value.as_i64().unwrap_or(0);
            let i = next(binds);
            binds.push(Bind::Int(n));
            let op = match c.operator {
                Gt => ">",
                Gte => ">=",
                Lt => "<",
                Lte => "<=",
                _ => unreachable!(),
            };
            format!("({expr}) {op} ${i}")
        }
        Between => {
            let lo = c.value.as_i64().unwrap_or(0);
            let hi = c.value_end.as_ref().and_then(|v| v.as_i64()).unwrap_or(lo);
            let ia = next(binds);
            binds.push(Bind::Int(lo));
            let ib = next(binds);
            binds.push(Bind::Int(hi));
            format!("(({expr}) >= ${ia} AND ({expr}) <= ${ib})")
        }
        Contains => {
            let v = c.value.as_str().unwrap_or("");
            let i = next(binds);
            binds.push(Bind::Text(format!("%{}%", escape_like(v))));
            format!("{expr} LIKE ${i}")
        }
        Regex => {
            let v = c.value.as_str().unwrap_or("");
            let i = next(binds);
            binds.push(Bind::Text(v.to_string()));
            format!("{expr} ~ ${i}")
        }
        In => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "FALSE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            format!("{expr} = ANY(${i}::text[])")
        }
        NotIn => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "TRUE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            // Match Rust: missing string (NULL) + not_in ⇒ NOT matched.
            format!("({expr} IS NOT NULL AND {expr} <> ALL(${i}::text[]))")
        }
    }
}

fn str_array(c: &Condition) -> Vec<String> {
    c.value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::condition::{Condition, ConditionOperator as Op, ConditionTarget as T};
    use crate::models::rule::{ConditionGroup, RuleTree};
    use serde_json::json;

    fn cond(t: T, op: Op, v: serde_json::Value) -> Condition {
        Condition {
            target: t,
            operator: op,
            value: v,
            value_end: None,
        }
    }

    #[test]
    fn grant_on_any_is_true() {
        let t = RuleTree {
            grant_on_any_relation: true,
            groups: vec![],
        };
        let (sql, binds) = build_rule_where(&t, 2);
        assert_eq!(sql, "TRUE");
        assert!(binds.is_empty());
    }

    #[test]
    fn convention_42_empty_is_false() {
        let t = RuleTree::default();
        let (sql, _) = build_rule_where(&t, 2);
        assert_eq!(sql, "FALSE");
    }

    #[test]
    fn single_group_ands() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![
                    cond(T::IsSubscriber, Op::Eq, json!(true)),
                    cond(T::SubMonthsCumulative, Op::Gte, json!(3)),
                ],
            }],
        };
        let (sql, binds) = build_rule_where(&t, 2);
        assert!(sql.contains(" AND "));
        assert!(sql.contains("COALESCE(cr.is_subscriber, false) = $3"));
        assert!(sql.contains(">= $4"));
        assert_eq!(binds.len(), 2);
        assert!(matches!(binds[0], Bind::Bool(true)));
        assert!(matches!(binds[1], Bind::Int(3)));
    }

    #[test]
    fn multi_group_ors() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![
                ConditionGroup {
                    conditions: vec![cond(T::IsSubscriber, Op::Eq, json!(true))],
                },
                ConditionGroup {
                    conditions: vec![cond(T::IsVip, Op::Eq, json!(true))],
                },
            ],
        };
        let (sql, binds) = build_rule_where(&t, 2);
        assert!(sql.contains(" OR "));
        assert_eq!(binds.len(), 2);
    }

    #[test]
    fn between_emits_two_binds() {
        let mut c = cond(T::SubMonthsCumulative, Op::Between, json!(3));
        c.value_end = Some(json!(12));
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![c],
            }],
        };
        let (sql, binds) = build_rule_where(&t, 0);
        assert!(sql.contains(">= $1") && sql.contains("<= $2"));
        assert_eq!(binds.len(), 2);
    }

    #[test]
    fn in_list_uses_text_array() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![cond(T::CountryCode, Op::In, json!(["US", "CA"]))],
            }],
        };
        let (sql, binds) = build_rule_where(&t, 2);
        assert!(sql.contains("= ANY($3::text[])"));
        assert!(matches!(&binds[0], Bind::TextArray(v) if v.len() == 2));
    }

    #[test]
    fn like_escapes_wildcards() {
        let t = RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![cond(T::Username, Op::Contains, json!("100%_real"))],
            }],
        };
        let (_, binds) = build_rule_where(&t, 2);
        match &binds[0] {
            Bind::Text(s) => assert_eq!(s, "%100\\%\\_real%"),
            _ => panic!("expected Text bind"),
        }
    }
}
