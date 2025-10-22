use {
    clap::{Args, ValueEnum},
    icann_rdap_common::{
        check::{traverse_checks, CheckClass, CheckParams, GetChecks},
        response::RdapResponse,
    },
    tracing::error,
};

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Check type.
    ///
    /// Specifies the type of checks to conduct on the RDAP.
    /// These are RDAP specific checks and not
    /// JSON validation which is done automatically. This
    /// argument may be specified multiple times to include
    /// multiple check types. If no check types are given,
    /// all check types are used.
    #[arg(short = 'C', long, required = false, value_enum)]
    check_type: Vec<CheckTypeArg>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum CheckTypeArg {
    /// Checks for specification warnings.
    SpecWarn,

    /// Checks for specficiation errors.
    SpecError,
}

pub fn to_check_classes(args: &CheckArgs) -> Vec<CheckClass> {
    if args.check_type.is_empty() {
        vec![CheckClass::Std95Warning, CheckClass::Std95Error]
    } else {
        args.check_type
            .iter()
            .map(|c| match c {
                CheckTypeArg::SpecWarn => CheckClass::Std95Warning,
                CheckTypeArg::SpecError => CheckClass::Std95Error,
            })
            .collect::<Vec<CheckClass>>()
    }
}

/// Print errors and returns true if a check is found.
pub fn check_rdap(rdap: RdapResponse, check_types: &[CheckClass]) -> bool {
    let checks = rdap.get_checks(CheckParams {
        root: &rdap,
        parent_type: rdap.get_type(),
        allow_unreg_ext: true,
    });
    traverse_checks(
        &checks,
        check_types,
        None,
        &mut |struct_tree, check_item| error!("{struct_tree} -> {check_item}"),
    )
}
