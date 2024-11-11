mod opts;
mod values;


use clap::Parser;
use ldap3::{LdapConnAsync, SearchEntry};
use rpassword;

use crate::opts::{Credentials, Opts};
use crate::values::{output_binary_values, output_string_values};


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
        .unwrap_or("(objectClass=*)");

    ldap.simple_bind(&bind_dn, &password)
        .await.expect("failed to bind to LDAP server");

    let (results, _response) = ldap.search(
        &o.base_dn,
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
