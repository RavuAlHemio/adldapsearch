mod opts;
mod values;


use std::borrow::Cow;

use clap::Parser;
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
use rpassword;

use crate::opts::{Credentials, Opts};
use crate::values::{output_binary_values, output_string_values};


const DEFAULT_FILTER: &str = "(objectClass=*)";


async fn find_base_dn(ldap: &mut Ldap) -> String {
    // query rootDSE
    const NO_ATTRS: [&str; 0] = [];
    let (results, _response) = ldap.search(
        "",
        Scope::Base,
        DEFAULT_FILTER,
        &NO_ATTRS,
    )
        .await.expect("failed to search for rootDSE")
        .success().expect("error while searching for rootDSE");
    for result_entry in results {
        let entry = SearchEntry::construct(result_entry);

        // take defaultNamingContext if available, first of namingContexts otherwise
        if let Some(dncs) = entry.attrs.get("defaultNamingContext") {
            // there should only be one value for defaultNamingContext, but y'know
            for dnc in dncs {
                return dnc.clone();
            }
        }
        if let Some(ncs) = entry.attrs.get("namingContexts") {
            for nc in ncs {
                return nc.clone();
            }
        }
    }
    panic!("failed to find base DN from rootDSE; please specify -b/--base-dn");
}


async fn run() {
    let o = Opts::parse();

    let (bind_dn, password) = if let Some(credentials_file) = o.credentials_file.as_ref() {
        let creds_file_string = match std::fs::read_to_string(credentials_file) {
            Ok(cfs) => cfs,
            Err(e) => panic!("failed to read credentials file {}: {}", credentials_file.display(), e),
        };
        let creds: Credentials = match toml::from_str(&creds_file_string) {
            Ok(c) => c,
            Err(e) => panic!("failed to parse credentials file {}: {}", credentials_file.display(), e),
        };
        if let Some(bind_dn) = o.bind_dn {
            (bind_dn, creds.password)
        } else {
            (creds.bind_dn, creds.password)
        }
    } else if let Some(bind_dn) = o.bind_dn {
        let password = rpassword::prompt_password("LDAP password: ")
            .expect("failed to read password");
        (bind_dn, password)
    } else {
        panic!("at least one of -D/--bind-dn or -c/--credentials-file must be given");
    };

    // connect to LDAP server
    let (conn, mut ldap) = LdapConnAsync::new(&o.url)
        .await.expect("failed to connect to LDAP server");
    ldap3::drive!(conn);

    let filter = o.filter.as_deref()
        .unwrap_or(DEFAULT_FILTER);

    ldap.simple_bind(&bind_dn, &password)
        .await.expect("failed to bind to LDAP server");

    let base_dn = match o.base_dn.as_deref() {
        Some(bdn) => Cow::Borrowed(bdn),
        None => Cow::Owned(find_base_dn(&mut ldap).await),
    };

    if o.avoid_sacl {
        const LDAP_SERVER_SD_FLAGS_OID: &str = "1.2.840.113556.1.4.801";
        // payload is a BER-encoded SEQUENCE { INTEGER }
        // where the INTEGER is a combination of these bitflags:
        // 0x1 = owner, 0x2 = group, 0x4 = DACL, 0x8 = SACL
        // with an unprivileged user, we can generally read owner, group and DACL and not SACL
        // (if we try, the relevant attribute simply isn't returned)
        const PAYLOAD: [u8; 5] = [
            0x30, // ASN.1 SEQUENCE
            0x03, // 3 bytes long
                0x02, // ASN.1 INTEGER
                0x01, // 1 byte long
                0x07, // owner | group | DACL
        ];
        let avoid_sacl_control = ldap3::controls::RawControl {
            ctype: LDAP_SERVER_SD_FLAGS_OID.to_owned(),
            crit: false,
            val: Some(PAYLOAD.to_vec()),
        };
        ldap.with_controls(avoid_sacl_control);
    }

    let (results, _response) = ldap.search(
        &base_dn,
        o.scope.into(),
        filter,
        o.attributes.as_slice(),
    )
        .await.expect("search failed")
        .success().expect("search returned error");
    for result_entry in results {
        let entry = SearchEntry::construct(result_entry);
        println!();
        println!("dn: {}", entry.dn);

        let mut str_keys: Vec<&String> = entry.attrs.keys().collect();
        str_keys.sort_unstable();
        for key in str_keys {
            let str_values = entry.attrs.get(key).unwrap();
            output_string_values(key, str_values);
        }

        let mut bin_keys: Vec<&String> = entry.bin_attrs.keys().collect();
        bin_keys.sort_unstable();
        for key in bin_keys {
            let bin_values = entry.bin_attrs.get(key).unwrap();
            output_binary_values(key, bin_values);
        }
    }
}


#[tokio::main]
async fn main() {
    run().await
}
