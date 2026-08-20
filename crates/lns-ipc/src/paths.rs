use std::path::PathBuf;

/// Everything below sits inside one directory ([`lns_spec::lns_home`]), so the
/// user has one thing to back up and `lns uninstall --purge` has one thing to
/// remove — `docs/cli-spec.md` §9.
pub fn cache_root() -> PathBuf {
    lns_spec::lns_home().join("cache")
}

pub fn data_root() -> PathBuf {
    lns_spec::lns_home().join("data")
}

pub fn build_cache_root() -> PathBuf {
    cache_root().join("builds")
}

pub fn short_run_id(id: &str) -> &str {
    id.char_indices().nth(12).map_or(id, |(i, _)| &id[..i])
}

pub fn audit_runs_root() -> PathBuf {
    data_root().join("runs")
}

pub fn audit_log_for_run(run_id: &str) -> PathBuf {
    audit_runs_root().join(run_id).join("audit.jsonl")
}

pub fn audit_anchor_for_run(run_id: &str) -> PathBuf {
    audit_runs_root().join(run_id).join("audit.anchor")
}

pub fn connection_ledger() -> PathBuf {
    data_root().join("ledger.jsonl")
}

pub fn connection_ledger_anchor() -> PathBuf {
    data_root().join("ledger.anchor")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_run_id_truncates_to_twelve_chars_and_passes_shorter_ids_through() {
        assert_eq!(
            short_run_id("1a2b3c4d0000000000000000000000aa"),
            "1a2b3c4d0000"
        );
        assert_eq!(short_run_id("abc"), "abc");
        assert_eq!(short_run_id(""), "");
    }

    #[test]
    fn short_run_id_truncates_on_a_char_boundary_for_tampered_multibyte_ids() {
        assert_eq!(short_run_id("abcdefghijké"), "abcdefghijké");
        assert_eq!(short_run_id("aaaaaaaaaaaéz"), "aaaaaaaaaaaé");
    }

    #[test]
    fn every_root_sits_inside_the_one_directory_a_purge_removes() {
        let home = lns_spec::lns_home();
        for path in [
            cache_root(),
            data_root(),
            build_cache_root(),
            audit_runs_root(),
            audit_log_for_run("42"),
            audit_anchor_for_run("42"),
            connection_ledger(),
            connection_ledger_anchor(),
        ] {
            assert!(
                path.starts_with(&home),
                "one directory holds everything lns keeps, so nothing may escape it; {path:?} is outside {home:?}"
            );
        }
    }

    #[test]
    fn audit_log_lives_under_data_root_so_it_outlives_the_ephemeral_run_dir() {
        let p = audit_log_for_run("42");
        assert_eq!(p, data_root().join("runs").join("42").join("audit.jsonl"));
        assert!(
            !p.starts_with(cache_root()),
            "the audit trail must outlive ephemeral run dirs, so it cannot live under cache_root: {p:?}"
        );
    }

    #[test]
    fn audit_runs_root_is_the_shared_base_of_every_per_run_log() {
        let root = audit_runs_root();
        assert_eq!(root, data_root().join("runs"));
        assert!(audit_log_for_run("42").starts_with(&root));
        assert!(audit_anchor_for_run("42").starts_with(&root));
    }

    #[test]
    fn audit_anchor_path_is_a_sibling_of_the_audit_log() {
        let log = audit_log_for_run("42");
        let anchor = audit_anchor_for_run("42");
        assert_eq!(anchor.parent(), log.parent());
        assert!(anchor.ends_with("runs/42/audit.anchor"));
    }

    #[test]
    fn build_cache_root_lives_under_cache_root_not_data_root() {
        let builds = build_cache_root();
        assert_eq!(builds, cache_root().join("builds"));
        assert!(
            !builds.starts_with(data_root()),
            "the build cache is reconstructible content, so it belongs under cache_root, not data_root"
        );
    }

    #[test]
    fn connection_ledger_lives_under_data_root_not_cache_root() {
        let ledger = connection_ledger();
        assert_eq!(ledger, data_root().join("ledger.jsonl"));
        assert!(
            !ledger.starts_with(cache_root()),
            "the ledger must outlive ephemeral run dirs, so it cannot live under cache_root: {ledger:?}"
        );
    }

    #[test]
    fn connection_ledger_anchor_is_a_sibling_of_the_ledger() {
        let ledger = connection_ledger();
        let anchor = connection_ledger_anchor();
        assert_eq!(anchor.parent(), ledger.parent());
        assert!(anchor.ends_with("ledger.anchor"));
    }
}
