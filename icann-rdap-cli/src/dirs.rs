use std::{
    fs::{create_dir_all, write},
    path::PathBuf,
};

use directories::ProjectDirs;
use lazy_static::lazy_static;

use crate::error::CliError;

pub(crate) const QUALIFIER: &str = "org";
pub(crate) const ORGANIZATION: &str = "ICANN";
pub(crate) const APPLICATION: &str = "rdap";

pub(crate) const ENV_FILE_NAME: &str = "rdap.env";

lazy_static! {
    pub(crate) static ref PROJECT_DIRS: ProjectDirs =
        ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
            .expect("unable to formulate project directories");
}

/// Initializes the directories to be used.
pub(crate) fn init() -> Result<(), CliError> {
    create_dir_all(PROJECT_DIRS.config_dir())?;
    create_dir_all(PROJECT_DIRS.cache_dir())?;
    if !config_path().exists() {
        let example_config = include_str!("rdap.env");
        write(config_path(), example_config)?;
    }
    Ok(())
}

pub(crate) fn config_path() -> PathBuf {
    PROJECT_DIRS.config_dir().join(ENV_FILE_NAME)
}
