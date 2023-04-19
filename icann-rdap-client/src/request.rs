use strum_macros::Display;

#[derive(Display)]
pub enum SourceType {
    #[strum(serialize = "Domain Registry")]
    DomainRegistry,
    #[strum(serialize = "Domain Registrar")]
    DomainRegistrar,
    #[strum(serialize = "Regional Internet Registry")]
    RegionalInternetRegistry,
    #[strum(serialize = "Local Internet Registry")]
    LocalInternetRegistry,
    #[strum(serialize = "Uncategorized Registry")]
    UncategorizedRegistry,
}

/// Represents meta data about the request.
pub struct RequestData<'a> {
    /// The request number. That is, request 1, request 2, etc...
    pub req_number: usize,

    /// A human-friendly name to identify the source of the information.
    /// Examples might be "registry", "registrar", etc...
    pub source_host: &'a str,

    /// Represents the type of source.
    pub source_type: SourceType,
}
