use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use ldap3::Scope;
use serde::{Deserialize, Serialize};


/// Queries an LDAP directory and attempts to decode attribute values specific to Active Directory.
#[derive(Parser)]
pub(crate) struct Opts {
    /// The URL of the LDAP server to connect to, such as `ldap://ldap.example.com/`,
    /// `ldap://ldap.example.com:3268/` or `ldaps://ldap.example.com/`.
    #[arg(short = 'H', long)]
    pub url: String,

    /// The base Distinguished Name at which to anchor the search.
    ///
    /// If not given, selects the `defaultNamingContext` (or, if missing, the first value of
    /// `namingContexts`) from the root DSE.
    ///
    /// Example: `dc=example,dc=com`
    #[arg(short = 'b', long)]
    pub base_dn: Option<String>,

    /// The Distinguished Name with which to bind (log in) to the LDAP server. The password is
    /// queried from the terminal.
    ///
    /// One of `-D`/`--bind-dn` and `-c`/`--credentials-file` must be specified.
    ///
    /// Example: `cn=Administrator,cn=Users,dc=example,dc=com` (any LDAP server),
    /// `EXAMPLE\\Administrator` (Active Directory only)
    #[arg(short = 'D', long)]
    pub bind_dn: Option<String>,

    /// A file containing login credentials in TOML format.
    ///
    /// One of `-D`/`--bind-dn` and `-c`/`--credentials-file` must be specified.
    ///
    /// An example of a credentials file:
    /// ```toml
    /// bind_dn = "cn=Administrator,cn=Users,dc=example,dc=com"
    /// password = "hunter2"
    /// ```
    #[arg(short = 'c', long)]
    pub credentials_file: Option<PathBuf>,

    /// The scope in which to perform the search:
    /// * `base`: the base DN is queried directly
    /// * `one-level`: the direct children of the base DN are queried
    /// * `subtree`: all descendants of the base DN are queried
    #[arg(short = 's', long)]
    pub scope: LdapScope,

    /// Requests that the server returns access control lists without the system ACL section.
    ///
    /// This is necessary if the account used to query the server has lower privileges. If such an
    /// account is used and this option is not active, certain attributes containing ACLs are not
    /// returned at all.
    #[arg(long)]
    pub avoid_sacl: bool,

    /// The LDAP filter by which to select relevant entries. The default is `(objectClass=*)`.
    pub filter: Option<String>,

    /// One or more attribute values to return. The special values `*` (return all user attributes)
    /// and `+` (return all operational attributes) can be used as well.
    pub attributes: Vec<String>,
}


#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, ValueEnum)]
pub(crate) enum LdapScope {
    Base,
    OneLevel,
    Subtree,
}
impl From<Scope> for LdapScope {
    fn from(value: Scope) -> Self {
        match value {
            Scope::Base => Self::Base,
            Scope::OneLevel => Self::OneLevel,
            Scope::Subtree => Self::Subtree,
        }
    }
}
impl From<LdapScope> for Scope {
    fn from(value: LdapScope) -> Self {
        match value {
            LdapScope::Base => Self::Base,
            LdapScope::OneLevel => Self::OneLevel,
            LdapScope::Subtree => Self::Subtree,
        }
    }
}


#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct Credentials {
    pub bind_dn: String,
    pub password: String,
}
