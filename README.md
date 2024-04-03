![](./.github/banner.png)

<p align="center">
  Extract all users from an Active Directory domain with password last set older than X days to an Excel worksheet. 
  <br>
  <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/DomainUsersToXLSX">
  <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
  <br>
</p>

## Features

 - [x] Extract all domain users with password last set older than X days to Excel worksheet
 - [x] Filters on columns of the table

## Usage

```
$ ./UsersWithPwdLastSetOlderThan.py -h                                                      
UsersWithPwdLastSetOlderThan v1.2 - by @podalirius_

usage: e.py [-h] [--use-ldaps] [-q] [-debug] [-no-colors] [-o OUTPUT_FILE] [-D DAYS] --dc-ip ip address [-d DOMAIN] [-u USER]
            [--no-pass | -p PASSWORD | -H [LMHASH:]NTHASH | --aes-key hex key] [-k]

Extract all users from an Active Directory domain to an Excel worksheet.

options:
  -h, --help            show this help message and exit
  --use-ldaps           Use LDAPS instead of LDAP
  -q, --quiet           Show no information at all.
  -debug                Debug mode.
  -no-colors            Disables colored output mode
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output file to store the results in. (default: accounts.xlsx)
  -D DAYS, --days DAYS  Number of days since last password change.

authentication & connection:
  --dc-ip ip address    IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in
                        the identity parameter
  -d DOMAIN, --domain DOMAIN
                        (FQDN) domain to authenticate to
  -u USER, --user USER  user to authenticate with

  --no-pass             Don't ask for password (useful for -k)
  -p PASSWORD, --password PASSWORD
                        Password to authenticate with
  -H [LMHASH:]NTHASH, --hashes [LMHASH:]NTHASH
                        NT/LM hashes, format is LMhash:NThash
  --aes-key hex key     AES key to use for Kerberos Authentication (128 or 256 bits)
  -k, --kerberos        Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be
                        found, it will use the ones specified in the command line

```

## Demonstration



## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
