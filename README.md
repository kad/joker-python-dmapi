# joker-python-dmapi

Python client and command line tool for the [Joker.com DMAPI](https://joker.com/faq/content/26/14/en/dmapi.html).
It can also act as a DNS-01 provider for [lego](https://github.com/go-acme/lego).

Requires Python 3.11 or newer.

## Install

```shell
pip install .
```

## Command line

Set `JOKER_API_KEY`, or `JOKER_USERNAME` and `JOKER_PASSWORD`. The options `-v`, `--json`,
`--backup-dir` and `--no-backup` work before or after the command.

Commands use the official DMAPI request names:

```shell
joker-dmapi dns-zone-list
joker-dmapi dns-zone-get example.com > zone.txt
joker-dmapi dns-zone-put example.com zone.txt
joker-dmapi present _acme-challenge.example.com. <value>
joker-dmapi cleanup _acme-challenge.example.com. <value>
```

The older names `get-zone`, `put-zone` and `list-zones` still work as aliases. `info` prints the
account details and zones.

Read-only queries:

| Command | Shows |
|---|---|
| `query-profile`, `query-account-balance` | reseller profile, balance |
| `query-domain-list [pattern]` | domains and expiry; `--show-status`, `--show-grants`, `--show-privacy` |
| `query-ns-list`, `query-contact-list` | name servers, contact handles |
| `query-order-list` | orders; `--after`, `--before`, `--type`, `--status`, `--fqdn-like`, `--show-all` |
| `domain-check <domain>` | availability; `--check-price create\|renew\|transfer\|restore` |
| `domain-get-property <domain> [name]` | one property, or all four documented ones (`autorenew`, `whois-opt-out`, `privacy`, `gdpr-opt-in`) when no name is given |
| `grants-list <domain>` | grants and invitations |
| `result-list`, `result-retrieve` | results of asynchronous requests |

Add `--json` for machine-readable output. Requests that spend money or delete things
(`domain-register`, `domain-delete` and so on) are not wrapped; use `Joker.request()` for those.

### Zone backups

`dns-zone-put` replaces the whole zone, and `present` and `cleanup` rewrite it. Before any zone
write, the CLI saves the current zone to `<domain>-<UTC timestamp>.zone` in:

1. `--backup-dir`, or
2. `$JOKER_BACKUP_DIR` (set it empty to turn backups off), or
3. `$XDG_STATE_HOME/joker-dmapi/backups`, which is `~/.local/state/joker-dmapi/backups` by default.

`--no-backup` skips the backup. If the backup can't be written, the zone is left unchanged. Files are
readable only by their owner, because a zone can hold DynDNS credentials. Old backups are not
removed. To roll back, run `dns-zone-put` with a backup file.

## Single-file executable

```shell
make pyz   # writes dist/joker-dmapi.pyz
```

The result is a zipapp with `requests` and its dependencies bundled. It runs on any machine with
Python 3.11+ and no install step. On first run it unpacks itself into `~/.shiv`.

```shell
JOKER_API_KEY=... ./dist/joker-dmapi.pyz info
```

## Usage with lego

lego runs the program as `present <FQDN> <value>` and `cleanup <FQDN> <value>`, which is the CLI syntax. Leave `EXEC_MODE` unset: `RAW` passes a token and key authorization instead, which this tool doesn't accept.

```shell
export JOKER_API_KEY=....
export EXEC_PATH=joker-dmapi   # or the full path to dist/joker-dmapi.pyz
lego -m admin@example.com -a --dns exec -d '*.example.com' run
```

## Development

```shell
make install   # uv sync
make check     # ruff, mypy, pytest
```

## Changes in 0.2.0

The client raises exceptions instead of returning `(code, text)` tuples. `find_domain_for_fdqn` is
renamed `find_domain_for_fqdn`, and `dns_zone_get` returns the zone as a string. On `JokerResponse`,
`as_separated_lists` is now `as_rows` and `as_list_of_dicts` is now `as_table`. The `cleanup` command
removes only the TXT record with the given value.
