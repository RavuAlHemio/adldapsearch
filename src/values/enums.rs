use from_to_repr::FromToRepr;


#[derive(Clone, Copy, Debug, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd)]
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
