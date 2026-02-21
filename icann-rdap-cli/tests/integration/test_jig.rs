use {
    assert_cmd::Command,
    icann_rdap_srv::{
        config::{JsContactConversion, ListenConfig},
        server::{AppState, Listener},
        storage::{
            mem::{config::MemConfig, ops::Mem},
            CommonConfig,
        },
    },
    std::time::Duration,
    test_dir::{DirBuilder, FileType, TestDir},
};

pub enum CommandType {
    Rdap,
    RdapTest,
}

pub struct TestJig {
    pub mem: Mem,
    pub cmd: Command,
    pub cmd_type: CommandType,
    pub rdap_base: String,
    // pass ownership to the test so the directories are dropped when the test is done.
    test_dir: TestDir,
}

impl TestJig {
    pub async fn new_rdap() -> Self {
        let common_config = CommonConfig::default();
        Self::new_common_config(common_config, CommandType::Rdap).await
    }

    pub async fn new_rdap_with_search() -> Self {
        let common_config = CommonConfig::builder()
            .domain_search_by_name_enable(true)
            .domain_search_by_ns_ip_enable(true)
            .domain_search_by_ns_ldh_name_enable(true)
            .nameserver_search_by_name_enable(true)
            .nameserver_search_by_ip_enable(true)
            .build();
        Self::new_common_config(common_config, CommandType::Rdap).await
    }

    pub async fn new_rdap_test() -> Self {
        let common_config = CommonConfig::default();
        Self::new_common_config(common_config, CommandType::RdapTest).await
    }

    pub async fn new_rdap_test_no_http_env() -> Self {
        let common_config = CommonConfig::default();
        Self::new_common_config_no_http_env(common_config, CommandType::RdapTest).await
    }

    pub async fn new_common_config_no_http_env(
        common_config: CommonConfig,
        cmd_type: CommandType,
    ) -> Self {
        let mem = Mem::new(MemConfig::builder().common_config(common_config).build());
        let app_state = AppState {
            storage: mem.clone(),
            bootstrap: false,
            jscontact_conversion: JsContactConversion::None,
        };
        let _ = tracing_subscriber::fmt().try_init();
        let listener = Listener::listen(&ListenConfig::default())
            .await
            .expect("listening on interface");
        let rdap_base = listener.rdap_base();
        tokio::spawn(async move {
            listener
                .start_with_state(app_state)
                .await
                .expect("starting server");
        });
        let test_dir = TestDir::temp()
            .create("cache", FileType::Dir)
            .create("config", FileType::Dir);
        let cmd = Command::new("sh"); //throw away
        Self {
            mem,
            cmd,
            cmd_type,
            rdap_base,
            test_dir,
        }
        .new_cmd_no_http_env()
    }

    pub async fn new_common_config(common_config: CommonConfig, cmd_type: CommandType) -> Self {
        let mem = Mem::new(MemConfig::builder().common_config(common_config).build());
        let app_state = AppState {
            storage: mem.clone(),
            bootstrap: false,
            jscontact_conversion: JsContactConversion::None,
        };
        let _ = tracing_subscriber::fmt().try_init();
        let listener = Listener::listen(&ListenConfig::default())
            .await
            .expect("listening on interface");
        let rdap_base = listener.rdap_base();
        tokio::spawn(async move {
            listener
                .start_with_state(app_state)
                .await
                .expect("starting server");
        });
        let test_dir = TestDir::temp()
            .create("cache", FileType::Dir)
            .create("config", FileType::Dir);
        let cmd = Command::new("sh"); //throw away
        Self {
            mem,
            cmd,
            cmd_type,
            rdap_base,
            test_dir,
        }
        .new_cmd()
    }

    /// Creates a new command from an existing one but resetting necessary environment variables.
    ///
    /// Using the function allows the test jig to stay up but a new command to be executed.
    pub fn new_cmd(self) -> Self {
        let cmd = match self.cmd_type {
            CommandType::Rdap => {
                let mut cmd = Command::cargo_bin("rdap").expect("cannot find rdap cmd");
                cmd.env_clear()
                    .timeout(Duration::from_secs(2))
                    .env("RDAP_BASE_URL", self.rdap_base.clone())
                    .env("RDAP_PAGING", "none")
                    .env("RDAP_OUTPUT", "json-extra")
                    .env("RDAP_LOG", "debug")
                    .env("RDAP_ALLOW_HTTP", "true")
                    .env("XDG_CACHE_HOME", self.test_dir.path("cache"))
                    .env("XDG_CONFIG_HOME", self.test_dir.path("config"));
                cmd
            }
            CommandType::RdapTest => {
                let mut cmd = Command::cargo_bin("rdap-test").expect("cannot find rdap-test cmd");
                cmd.env_clear()
                    .timeout(Duration::from_secs(2))
                    .env("RDAP_TEST_LOG", "debug")
                    .env("RDAP_TEST_ALLOW_HTTP", "true")
                    .env("XDG_CACHE_HOME", self.test_dir.path("cache"))
                    .env("XDG_CONFIG_HOME", self.test_dir.path("config"));
                cmd
            }
        };
        Self { cmd, ..self }
    }

    pub fn new_cmd_no_http_env(self) -> Self {
        let cmd = match self.cmd_type {
            CommandType::Rdap => {
                let mut cmd = Command::cargo_bin("rdap").expect("cannot find rdap cmd");
                cmd.env_clear()
                    .timeout(Duration::from_secs(2))
                    .env("RDAP_BASE_URL", self.rdap_base.clone())
                    .env("RDAP_PAGING", "none")
                    .env("RDAP_OUTPUT", "json-extra")
                    .env("RDAP_LOG", "debug")
                    .env("XDG_CACHE_HOME", self.test_dir.path("cache"))
                    .env("XDG_CONFIG_HOME", self.test_dir.path("config"));
                cmd
            }
            CommandType::RdapTest => {
                let mut cmd = Command::cargo_bin("rdap-test").expect("cannot find rdap-test cmd");
                cmd.env_clear()
                    .timeout(Duration::from_secs(2))
                    .env("RDAP_TEST_LOG", "debug")
                    .env("XDG_CACHE_HOME", self.test_dir.path("cache"))
                    .env("XDG_CONFIG_HOME", self.test_dir.path("config"));
                cmd
            }
        };
        Self { cmd, ..self }
    }

    pub fn config_dir(&self) -> String {
        self.test_dir.path("config").to_string_lossy().to_string()
    }
}
