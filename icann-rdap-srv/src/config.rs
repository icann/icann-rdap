use buildstructor::Builder;

/// RDAP server listening configuration.
#[derive(Debug, Builder)]
pub struct ListenConfig {
    /// If specified, determines the IP address of the interface to bind to.
    /// If unspecified, the server will bind all interfaces.
    pub ip_addr: Option<String>,

    /// If specified, determines the port number the server will bind to.
    /// If unspecified, the server let's the OS determine the port.
    pub port: Option<u32>,
}

/// RDAP service configuration.
#[derive(Debug, Builder)]
pub struct ServiceConfig {}
