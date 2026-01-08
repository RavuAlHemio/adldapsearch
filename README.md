# adldapsearch

Tool for querying Active Directory and outputting human-readable representations of some attributes
with binary value structures.

## Usage

```sh
adlapsearch -H "ldaps://dc1.corp.example.com" -b "dc=corp,dc=example,dc=com" -D "CORP\\jdoe" -s subtree
```

Credentials can either be provided interactively (bind DN via `-D` and password via terminal) or
through a credentials file (`-c filename.toml`) with content like this:

```toml
bind_dn = "CORP\\jdoe"
password = "hunter2"
```

An LDAP filter and a list of attributes may be passed at the end of the command line like with
OpenLDAP's `ldapsearch`.

The following creature comforts are available:

* `-p`/`--paginate PAGESIZE` activates the LDAP pagination control when querying, allowing the
  server to respond in multiple partial batches instead of attempting to provide all information at
  once.

* `--avoid-sacl` activates the Security Data Flags control when querying and requests that security
  data only contains the owner, group and Discretionary Access Control List (permissions), but not
  the System Access Control List (auditing settings). This is necessary when querying security data
  (e.g. `nTSecurityDescriptor`) as a non-administrative user, since otherwise the values of these
  attributes are not returned at all.
