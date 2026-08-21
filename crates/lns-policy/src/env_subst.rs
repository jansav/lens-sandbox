/// Replaces each literal `${NAME}` in `src` with its mapped value; an unmapped reference is left untouched.
pub(crate) fn apply_substitutions(src: &str, subs: &[(&str, &str)]) -> String {
    let mut out = src.to_string();
    for (name, value) in subs {
        out = out.replace(&format!("${{{name}}}"), value);
    }
    out
}

/// Resolves every `${NAME}` the source references against the process environment, so a real client id lives in the environment rather than the document.
pub(crate) fn resolve_from_env(src: &str) -> String {
    let names = referenced_names(src);
    let subs: Vec<(String, String)> = names
        .into_iter()
        .filter_map(|name| std::env::var(&name).ok().map(|value| (name, value)))
        .collect();
    let borrowed: Vec<(&str, &str)> = subs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    apply_substitutions(src, &borrowed)
}

fn referenced_names(src: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = src;
    while let Some(open) = rest.find("${") {
        rest = &rest[open + 2..];
        let Some(close) = rest.find('}') else { break };
        let name = &rest[..close];
        if !name.is_empty() && !names.iter().any(|n: &String| n == name) {
            names.push(name.to_string());
        }
        rest = &rest[close + 1..];
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial(env)]
    fn resolve_from_env_replaces_only_names_the_environment_holds() {
        let _g1 = crate::test_env::EnvVarGuard::set("LNS_TEST_ONE", "1");
        let _g2 = crate::test_env::EnvVarGuard::unset("LNS_TEST_TWO");
        assert_eq!(
            resolve_from_env("a=${LNS_TEST_ONE} b=${LNS_TEST_TWO}"),
            "a=1 b=${LNS_TEST_TWO}",
            "an unset reference stays literal so a consumer can tell it apart from a value"
        );
    }

    #[test]
    #[serial_test::serial(env)]
    fn resolve_from_env_replaces_every_occurrence_of_one_name() {
        let _g = crate::test_env::EnvVarGuard::set("LNS_TEST_ONE", "x");
        assert_eq!(resolve_from_env("${LNS_TEST_ONE}-${LNS_TEST_ONE}"), "x-x");
    }

    #[test]
    fn an_unterminated_reference_is_left_alone() {
        assert_eq!(resolve_from_env("a=${UNCLOSED"), "a=${UNCLOSED");
    }

    #[test]
    fn source_without_references_is_returned_unchanged() {
        assert_eq!(apply_substitutions("k: plain", &[]), "k: plain");
    }

    #[test]
    fn a_present_reference_is_replaced_with_its_value() {
        assert_eq!(
            apply_substitutions("k: \"${SOME_VAR}\"", &[("SOME_VAR", "SOME_TOKEN")]),
            "k: \"SOME_TOKEN\""
        );
    }

    #[test]
    fn a_reference_mapped_to_empty_becomes_an_empty_string() {
        assert_eq!(
            apply_substitutions("k: \"${SOME_VAR}\"", &[("SOME_VAR", "")]),
            "k: \"\""
        );
    }

    #[test]
    fn a_repeated_reference_is_replaced_everywhere() {
        assert_eq!(
            apply_substitutions("${SOME_VAR}-${SOME_VAR}", &[("SOME_VAR", "x")]),
            "x-x"
        );
    }

    #[test]
    fn multiple_distinct_references_each_resolve() {
        assert_eq!(
            apply_substitutions("a=${ONE} b=${TWO}", &[("ONE", "1"), ("TWO", "2")]),
            "a=1 b=2"
        );
    }

    #[test]
    fn an_unmapped_reference_is_left_literal() {
        assert_eq!(apply_substitutions("k: ${SOME_VAR}", &[]), "k: ${SOME_VAR}");
    }

    #[test]
    fn a_substitution_whose_name_is_absent_from_the_source_is_a_no_op() {
        assert_eq!(apply_substitutions("plain", &[("ABSENT", "v")]), "plain");
    }
}
