use crate::error::RdapServerError;

#[derive(Debug)]
pub struct DbUrlParts {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub database: String,
}

impl DbUrlParts {
    pub fn from_url(url: &str) -> Result<Self, RdapServerError> {
        let url = url
            .strip_prefix("postgresql://")
            .or_else(|| url.strip_prefix("postgres://"))
            .ok_or_else(|| RdapServerError::Config(format!("invalid database URL: {}", url)))?;

        let (rest, database) = url
            .rsplit_once('/')
            .ok_or_else(|| RdapServerError::Config(format!("invalid database URL: {}", url)))?;

        let (userpass, hostport) = if let Some(up) = rest.rsplit_once('@') {
            (Some(up.0), up.1)
        } else {
            (None, rest)
        };

        let (user, password) = if let Some(userpass) = userpass {
            if let Some((u, p)) = userpass.split_once(':') {
                (u.to_string(), Some(p.to_string()))
            } else {
                (userpass.to_string(), None)
            }
        } else {
            ("postgres".to_string(), None)
        };

        let (host, port) = if hostport.contains(':') {
            let (h, p) = hostport
                .rsplit_once(':')
                .ok_or_else(|| RdapServerError::Config(format!("invalid database URL: {}", url)))?;
            let port: u16 = p.parse().map_err(|_| {
                RdapServerError::Config(format!("invalid port in database URL: {}", url))
            })?;
            (h.to_string(), port)
        } else {
            (hostport.to_string(), 5432)
        };

        Ok(Self {
            host,
            port,
            user,
            password,
            database: database.to_string(),
        })
    }

    pub fn to_superuser_url(&self, admin_user: &str, admin_password: Option<&str>) -> String {
        if let Some(admin_password) = admin_password {
            format!(
                "postgresql://{admin_user}:{admin_password}@{}:{}/postgres",
                self.host, self.port
            )
        } else {
            format!(
                "postgresql://{admin_user}@{}:{}/postgres",
                self.host, self.port
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_url() {
        // GIVEN

        // WHEN
        let parts = DbUrlParts::from_url("postgresql://127.0.0.1/rdap").expect("parse url");

        // THEN
        assert_eq!(parts.host, "127.0.0.1");
        assert_eq!(parts.port, 5432);
        assert_eq!(parts.user, "postgres");
        assert_eq!(parts.password, None);
        assert_eq!(parts.database, "rdap");
    }

    #[test]
    fn test_parse_url_with_user() {
        // GIVEN

        // WHEN
        let parts =
            DbUrlParts::from_url("postgresql://rdap_user@localhost/rdap_db").expect("parse url");

        // THEN
        assert_eq!(parts.host, "localhost");
        assert_eq!(parts.port, 5432);
        assert_eq!(parts.user, "rdap_user");
        assert_eq!(parts.password, None);
        assert_eq!(parts.database, "rdap_db");
    }

    #[test]
    fn test_parse_url_with_port() {
        // GIVEN

        // WHEN
        let parts = DbUrlParts::from_url("postgresql://rdap_user@10.0.0.1:5433/rdap_db")
            .expect("parse url");

        // THEN
        assert_eq!(parts.host, "10.0.0.1");
        assert_eq!(parts.port, 5433);
        assert_eq!(parts.user, "rdap_user");
        assert_eq!(parts.password, None);
        assert_eq!(parts.database, "rdap_db");
    }

    #[test]
    fn test_parse_url_with_password() {
        // GIVEN

        // WHEN
        let parts = DbUrlParts::from_url(
            "postgresql://postgres:MySecurePass123@localhost:5432/my_database",
        )
        .expect("parse url");

        // THEN
        assert_eq!(parts.host, "localhost");
        assert_eq!(parts.port, 5432);
        assert_eq!(parts.user, "postgres");
        assert_eq!(parts.password, Some("MySecurePass123".to_string()));
        assert_eq!(parts.database, "my_database");
    }

    #[test]
    fn test_superuser_url() {
        // GIVEN

        // WHEN
        let parts = DbUrlParts::from_url("postgresql://rdap_user@127.0.0.1:5432/rdap_db")
            .expect("parse url");

        // THEN
        assert_eq!(
            parts.to_superuser_url("postgres", None),
            "postgresql://postgres@127.0.0.1:5432/postgres"
        );
    }

    #[test]
    fn test_superuser_url_with_password() {
        // GIVEN

        // WHEN
        let parts = DbUrlParts::from_url("postgresql://rdap_user@127.0.0.1:5432/rdap_db")
            .expect("parse url");

        // THEN
        assert_eq!(
            parts.to_superuser_url("postgres", Some("supersecret")),
            "postgresql://postgres:supersecret@127.0.0.1:5432/postgres"
        );
    }
}
