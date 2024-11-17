use from_to_repr::{from_to_other, FromToRepr};
use serde::{Deserialize, Serialize};


// https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype
#[derive(Clone, Copy, Debug, Deserialize, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u32)]
pub(crate) enum SamAccountType {
    DomainObject = 0x0,
    GroupObject = 0x10000000,
    NonSecurityGroupObject = 0x10000001,
    AliasObject = 0x20000000,
    NonSecurityAliasObject = 0x20000001,
    UserObject = 0x30000000,
    MachineAccount = 0x30000001,
    TrustAccount = 0x30000002,
    AppBasicGroup = 0x40000000,
    AppQueryGroup = 0x40000001,
    AccountTypeMax = 0x7fffffff,
}


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d49624d0-9320-4368-8b0c-a7998ac2abdb
#[derive(Clone, Copy, Debug, Deserialize, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u32)]
pub(crate) enum FunctionalityLevel {
    Win2000 = 0,
    Win2003Mixed = 1,
    Win2003 = 2,
    Win2008 = 3,
    Win2008R2 = 4,
    Win2012 = 5,
    Win2012R2 = 6,
    Win2016 = 7,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/36565693-b5e4-4f37-b0a8-c1b12138e18e
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub(crate) enum TrustType {
    Downlevel = 0x00000001,
    Uplevel = 0x00000002,
    Mit = 0x00000003,
    Dce = 0x00000004,
    AzureActiveDirectory = 0x00000005,
    Other(u32),
}
