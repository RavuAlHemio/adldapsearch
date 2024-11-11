use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use ldap3::Scope;
use serde::{Deserialize, Serialize};


#[derive(Parser)]
pub(crate) struct Opts {
    #[arg(short = 'H', long)]
    pub url: String,

    #[arg(short = 'b', long)]
    pub base_dn: String,

    #[arg(short = 'D', long)]
    pub bind_dn: Option<String>,

    #[arg(short = 'c', long)]
    pub credentials_file: Option<PathBuf>,

    #[arg(short = 's', long)]
    pub scope: LdapScope,

    pub filter: Option<String>,

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
