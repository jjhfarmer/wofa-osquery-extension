# osquery Extension: WOFA

An [osquery](https://osquery.io) extension that surfaces Windows patch and CVE data from [WOFA](https://wofa.dev/) (Windows Organised Feed for Admins) database as queryable tables.

WOFA aggregates Microsoft's monthly Patch Tuesday releases: build versions, CVE counts, exploitation status, and CISA KEV flags across all tracked Windows 10, 11, and Server versions. This extension makes that data available inside osquery so you can query it directly, build FleetDM Policies around it, and join it against device inventory data.

This project is inspired by the [MacAdmins osquery extension](https://github.com/macadmins/osquery-extension) and its SOFA tables for macOS. WOFA is the Windows equivalent, created by [Josh Tucker](https://github.com/Josh-Tucker/WOFA).

---

## Tables

### `wofa_security_release_info`

One row per OS version × security release. Returns the full release history tracked by the feed.

```sql
-- All releases for all OS versions
SELECT * FROM wofa_security_release_info;

-- Latest release info for a specific version
SELECT update_name, product_version, release_date, unique_cves_count
FROM wofa_security_release_info
WHERE os_version = 'Windows 11 24H2'
ORDER BY release_date DESC
LIMIT 1;

-- Find versions approaching end of support
SELECT os_version, support_end_home_pro, support_end_enterprise
FROM wofa_security_release_info
GROUP BY os_version;
```

| Column | Type | Description |
|---|---|---|
| `os_version` | TEXT | e.g. `Windows 11 24H2` |
| `update_name` | TEXT | KB article title |
| `release_date` | TEXT | `YYYY-MM-DD` |
| `product_version` | TEXT | Full build string, e.g. `10.0.26100.3476` |
| `security_info` | TEXT | URL to the Microsoft KB support article |
| `unique_cves_count` | INTEGER | Total distinct CVEs patched in this release |
| `actively_exploited_cves` | TEXT | Comma-separated list of actively exploited CVE IDs |
| `days_since_previous_release` | INTEGER | Days elapsed since the previous release |
| `supersedes` | TEXT | KB number of the update this release supersedes |
| `patch_tuesday_release` | INTEGER | `1` for regular Patch Tuesday, `0` for out-of-band |
| `support_end_home_pro` | TEXT | End-of-servicing date for Home/Pro editions |
| `support_end_enterprise` | TEXT | End-of-servicing date for Enterprise/Education editions |
| `url` | TEXT | Feed URL (overridable via `WHERE url = ...`) |

---

### `wofa_unpatched_cves`

One row per actively-exploited CVE that has **not yet been patched** on the queried device. The extension determines the device's current Windows build from osquery's `os_version` table and returns only CVEs from newer releases — i.e. fixes the device is missing.

```sql
-- CVEs not yet patched on this device
SELECT cve_id, severity, cvss_score, in_kev, patched_in_version
FROM wofa_unpatched_cves;

-- Only CISA Known Exploited Vulnerabilities
SELECT cve_id, severity, cvss_score, nist_url
FROM wofa_unpatched_cves
WHERE in_kev = 1;

-- Query a specific build (useful for cross-device analysis in Fleet)
SELECT * FROM wofa_unpatched_cves WHERE os_version = '10.0.26100.3000';
```

| Column | Type | Description |
|---|---|---|
| `os_version` | TEXT | Device build string (from `os_version` table, or `WHERE` clause) |
| `cve_id` | TEXT | CVE identifier, e.g. `CVE-2025-24985` |
| `severity` | TEXT | Critical / Important / Moderate / Low |
| `cvss_score` | TEXT | CVSS v3 base score |
| `in_kev` | INTEGER | `1` if listed in the CISA Known Exploited Vulnerabilities catalog |
| `patched_in_version` | TEXT | The build version that first patched this CVE |
| `nist_url` | TEXT | Link to the NIST NVD entry |
| `url` | TEXT | Feed URL (overridable via `WHERE url = ...`) |

---

## Installation

### Pre-built binary

Download the latest `wofa_extension.exe` from the [Releases](https://github.com/jjhfarmer/wofa-osquery-extension/releases) page.

### Build from source

Requires [Go 1.21+](https://go.dev/dl/).

```sh
git clone https://github.com/jjhfarmer/wofa-osquery-extension.git
cd wofa-osquery-extension

# Windows (native)
go build -ldflags "-X main.Version=$(cat VERSION)" -o wofa_extension.exe .

# Cross-compile from macOS/Linux
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.Version=$(cat VERSION)" -o wofa_extension.exe .
```

---

## Deployment with Fleet

Fleet supports osquery extensions natively via the [Extensions feature](https://fleetdm.com/docs/using-fleet/extensions). Upload `wofa_extension.exe` through the Fleet UI or with `fleetctl`, and Fleet will distribute it to enrolled Windows hosts via `orbit`.

Once deployed, both tables become available in Fleet's query interface and can be used in policies.

**Example Fleet policy — device is missing a patch with an exploited CVE:**
```sql
SELECT 1 FROM wofa_unpatched_cves WHERE in_kev = 1 LIMIT 1;
```

---

## Manual usage

```sh
osqueryi.exe --extension wofa_extension.exe
```

```sql
osquery> SELECT * FROM wofa_security_release_info WHERE os_version = 'Windows 11 24H2';
osquery> SELECT cve_id, severity, in_kev FROM wofa_unpatched_cves;
```

---

## Development

```sh
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...
```

Tests use an embedded JSON fixture (`tables/wofa/test_data.json`) and do not make network requests.

### Adding a new table

1. Create `tables/<tablename>/<tablename>.go` with `Columns()` and `Generate()` functions
2. Add a `<tablename>_test.go` alongside it
3. Register the plugin in `main.go`

See the existing `tables/wofa/` package as a reference.

---

## Data source

All data comes from [WOFA](https://wofa.dev), a community project by [Josh Tucker](https://github.com/Josh-Tucker/WOFA) that aggregates data from:

- [Microsoft Security Response Center (MSRC) CVRF API](https://api.msrc.microsoft.com/)
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

The feed is updated every 6 hours. This extension fetches it on demand with a 10-second timeout; if the feed is unreachable the tables return empty rows rather than an error.

---

## Contributing

Contributions are welcome. If you have ideas for additional Windows security tables, please open an issue first to discuss the approach before submitting a pull request.

---

## License

[Apache 2.0](LICENSE)

