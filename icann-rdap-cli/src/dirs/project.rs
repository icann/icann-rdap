use std::{
    fs::{create_dir_all, remove_dir_all, write},
    io::Error,
    path::PathBuf,
    sync::LazyLock,
};

use directories::ProjectDirs;

pub const QUALIFIER: &str = "org";
pub const ORGANIZATION: &str = "ICANN";
pub const APPLICATION: &str = "rdap";

pub const ENV_FILE_NAME: &str = "rdap.env";
pub const RDAP_CACHE_NAME: &str = "rdap_cache";
pub const BOOTSTRAP_CACHE_NAME: &str = "bootstrap_cache";

pub(crate) static PROJECT_DIRS: LazyLock<ProjectDirs> = LazyLock::new(|| {
    ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
        .expect("unable to formulate project directories")
});

/// Returns the user's download directory, or a fallback path.
fn get_download_dir() -> Option<PathBuf> {
    directories::UserDirs::new().and_then(|dirs| dirs.download_dir().map(|p| p.to_path_buf()))
}

/// Initializes the directories to be used.
pub fn init() -> Result<(), Error> {
    create_dir_all(PROJECT_DIRS.config_dir())?;
    create_dir_all(PROJECT_DIRS.cache_dir())?;
    create_dir_all(rdap_cache_path())?;
    create_dir_all(bootstrap_cache_path())?;

    // create default config file
    if !config_path().exists() {
        let example_config = include_str!("rdap.env");
        write(config_path(), example_config)?;
    }
    Ok(())
}

/// Reset the directories.
pub fn reset() -> Result<(), Error> {
    remove_dir_all(PROJECT_DIRS.config_dir())?;
    remove_dir_all(PROJECT_DIRS.cache_dir())?;
    init()
}

/// Returns a [PathBuf] to the configuration file.
pub fn config_path() -> PathBuf {
    if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg_config).join(ENV_FILE_NAME)
    } else {
        PROJECT_DIRS.config_dir().join(ENV_FILE_NAME)
    }
}

/// Returns a [PathBuf] to the configuration directory.
pub fn config_dir() -> PathBuf {
    config_path().parent().unwrap().to_path_buf()
}

/// Returns a [PathBuf] to the cache directory for RDAP responses.
pub fn rdap_cache_path() -> PathBuf {
    PROJECT_DIRS.cache_dir().join(RDAP_CACHE_NAME)
}

/// Returns a [PathBuf] to the cache directory for bootstrap files.
pub fn bootstrap_cache_path() -> PathBuf {
    if let Ok(xdg_cache) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(xdg_cache).join(BOOTSTRAP_CACHE_NAME)
    } else {
        PROJECT_DIRS.cache_dir().join(BOOTSTRAP_CACHE_NAME)
    }
}

/// Returns a [PathBuf] to the geofeed download directory.
///
/// Uses the user's system download directory (from the directories crate) with a
/// 'geofeed' subdirectory. Creates the directory if it doesn't exist.
pub fn geofeed_download_path() -> Result<PathBuf, Error> {
    let base = std::env::var("RDAP_DOWNLOAD_DIR")
        .map(PathBuf::from)
        .ok()
        .or_else(get_download_dir)
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| Error::other("unable to determine download directory"))?;
    let geofeed_dir = base.join("geofeed");
    create_dir_all(&geofeed_dir)?;
    Ok(geofeed_dir)
}
