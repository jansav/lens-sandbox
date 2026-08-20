use std::ffi::OsString;
use std::path::PathBuf;

/// The one directory everything `lns` keeps for the user lives in, specified in
/// `docs/cli-spec.md` §9. One directory to back up, and one for
/// `lns uninstall --purge` to remove.
pub fn lns_home() -> PathBuf {
    resolve(|key| std::env::var_os(key))
}

fn resolve(env: impl Fn(&str) -> Option<OsString>) -> PathBuf {
    if let Some(explicit) = env("LNS_HOME") {
        return PathBuf::from(explicit);
    }
    env("HOME")
        .map(|home| PathBuf::from(home).join(".lns"))
        .unwrap_or_else(|| PathBuf::from(".lns"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let owned: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), OsString::from(*v)))
            .collect();
        move |key| owned.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    #[test]
    fn lns_home_is_the_dot_lns_directory_under_home() {
        assert_eq!(
            resolve(env_of(&[("HOME", "/home/dev")])),
            PathBuf::from("/home/dev/.lns")
        );
    }

    #[test]
    fn lns_home_names_the_directory_itself_so_no_dot_lns_is_appended() {
        assert_eq!(
            resolve(env_of(&[
                ("LNS_HOME", "/srv/lns-state"),
                ("HOME", "/home/dev")
            ])),
            PathBuf::from("/srv/lns-state"),
            "LNS_HOME replaces the whole directory, so appending `.lns` would put state somewhere the user did not name"
        );
    }

    #[test]
    fn a_missing_home_falls_back_to_the_working_directory_rather_than_panicking() {
        assert_eq!(resolve(env_of(&[])), PathBuf::from(".lns"));
    }
}
