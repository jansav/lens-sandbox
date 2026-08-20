use std::path::PathBuf;

pub fn root() -> PathBuf {
    lns_ipc::cache_root()
}
