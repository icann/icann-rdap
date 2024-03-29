use std::{
    fs::{create_dir_all, remove_dir_all, write},
    path::PathBuf,
};

use directories::ProjectDirs;
use lazy_static::lazy_static;

use crate::error::CliError;

pub(crate) const QUALIFIER: &str = "org";
pub(crate) const ORGANIZATION: &str = "ICANN";
pub(crate) const APPLICATION: &str = "rdap";

pub(crate) const ENV_FILE_NAME: &str = "rdap.env";
pub(crate) const RDAP_CACHE_NAME: &str = "rdap_cache";
pub(crate) const BOOTSTRAP_CACHE_NAME: &str = "bootstrap_cache";

lazy_static! {
    pub(crate) static ref PROJECT_DIRS: ProjectDirs =
        ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
            .expect("unable to formulate project directories");
}

/// Initializes the directories to be used.
pub(crate) fn init() -> Result<(), CliError> {
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
pub(crate) fn reset() -> Result<(), CliError> {
    remove_dir_all(PROJECT_DIRS.config_dir())?;
    remove_dir_all(PROJECT_DIRS.cache_dir())?;
    init()
}

/// Returns a [PathBuf] to the configuration file.
pub(crate) fn config_path() -> PathBuf {
    PROJECT_DIRS.config_dir().join(ENV_FILE_NAME)
}

/// Returns a [PathBuf] to the cache directory for RDAP responses.
pub(crate) fn rdap_cache_path() -> PathBuf {
    PROJECT_DIRS.cache_dir().join(RDAP_CACHE_NAME)
}

/// Returns a [PathBuf] to the cache directory for bootstrap files.
pub(crate) fn bootstrap_cache_path() -> PathBuf {
    PROJECT_DIRS.cache_dir().join(BOOTSTRAP_CACHE_NAME)
}
