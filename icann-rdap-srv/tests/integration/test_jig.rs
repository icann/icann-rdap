use assert_cmd::Command;
use icann_rdap_srv::config::ListenConfig;
use icann_rdap_srv::server::AppState;
use icann_rdap_srv::server::Listener;
use icann_rdap_srv::storage::mem::ops::Mem;
use std::time::Duration;
use test_dir::DirBuilder;
use test_dir::TestDir;

pub struct RdapSrvStoreTestJig {
    pub cmd: Command,
    pub source_dir: TestDir,
    pub data_dir: TestDir,
}

impl RdapSrvStoreTestJig {
    pub fn new() -> RdapSrvStoreTestJig {
        let source_dir = TestDir::temp();
        let data_dir = TestDir::temp();
        let mut cmd = Command::cargo_bin("rdap-srv-store").expect("cannot find rdap-srv-store cmd");
        cmd.env_clear()
            .timeout(Duration::from_secs(2))
            .env("RDAP_BASE_URL", "http://localhost:3000/rdap")
            .env("RDAP_SRV_LOG", "debug")
            .env("RDAP_SRV_DATA_DIR", data_dir.root());
        RdapSrvStoreTestJig {
            cmd,
            source_dir,
            data_dir,
        }
    }
}

pub struct RdapSrvDataTestJig {
    pub cmd: Command,
    pub source_dir: TestDir,
    pub data_dir: TestDir,
}

impl RdapSrvDataTestJig {
    pub fn new() -> RdapSrvDataTestJig {
        let source_dir = TestDir::temp();
        let data_dir = TestDir::temp();
        let mut cmd = Command::cargo_bin("rdap-srv-data").expect("cannot find rdap-srv-data cmd");
        cmd.env_clear()
            .timeout(Duration::from_secs(2))
            .env("RDAP_BASE_URL", "http://localhost:3000/rdap")
            .env("RDAP_SRV_LOG", "debug")
            .env("RDAP_SRV_DATA_DIR", data_dir.root());
        RdapSrvDataTestJig {
            cmd,
            source_dir,
            data_dir,
        }
    }

    pub fn new_cmd(self) -> RdapSrvDataTestJig {
        let mut cmd = Command::cargo_bin("rdap-srv-data").expect("cannot find rdap-srv-data cmd");
        cmd.env_clear()
            .timeout(Duration::from_secs(2))
            .env("RDAP_BASE_URL", "http://localhost:3000/rdap")
            .env("RDAP_SRV_LOG", "debug")
            .env("RDAP_SRV_DATA_DIR", self.data_dir.root());
        RdapSrvDataTestJig {
            cmd,
            source_dir: self.source_dir,
            data_dir: self.data_dir,
        }
    }
}

pub struct SrvTestJig {
    pub mem: Mem,
    pub rdap_base: String,
}

impl SrvTestJig {
    pub fn new() -> SrvTestJig {
        let mem = Mem::default();
        let app_state = AppState {
            storage: mem.clone(),
        };
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let listener = Listener::listen(&ListenConfig::default()).expect("listening on interface");
        let rdap_base = listener.rdap_base();
        tokio::spawn(async move {
            listener
                .start_with_state(app_state)
                .await
                .expect("starting server");
        });
        SrvTestJig { mem, rdap_base }
    }
}
