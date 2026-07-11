package wofa

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

// Define schema
func WofaUnpatchedCVEsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("os_version"),
		table.TextColumn("cve_id"),
		table.TextColumn("severity"),
		table.TextColumn("cvss_score"),
		table.IntegerColumn("in_kev"),
		table.TextColumn("patched_in_version"),
		table.TextColumn("nist_url"),
		table.TextColumn("url"),
	}
}

// WofaUnpatchedCVEsGenerate returns one row per actively-exploited CVE that has
// not yet been applied to the queried device. It determines the device's current
// Windows build from osquery's os_version table via the socket, then finds all
// security releases newer than that build and surfaces their exploited CVEs.
//
// The os_version column can be supplied in a WHERE clause to target a specific
// build instead of querying the local device:
//
//	SELECT * FROM wofa_unpatched_cves WHERE os_version = '10.0.26100.3000'
func WofaUnpatchedCVEsGenerate(
	ctx context.Context,
	queryContext table.QueryContext,
	socketPath string,
	opts ...Option,
) ([]map[string]string, error) {
	url := WofaV1URL
	if cl, present := queryContext.Constraints["url"]; present {
		for _, c := range cl.Constraints {
			if c.Operator == table.OperatorEquals {
				url = c.Expression
			}
		}
	}

	// Allow the caller to supply a build string directly, bypassing the socket
	// query. This is useful for cross-device analysis in Fleet.
	deviceBuild := ""
	if cl, present := queryContext.Constraints["os_version"]; present {
		for _, c := range cl.Constraints {
			if c.Operator == table.OperatorEquals {
				deviceBuild = c.Expression
			}
		}
	}

	if deviceBuild == "" {
		var err error
		deviceBuild, err = getCurrentWindowsBuild(socketPath)
		if err != nil {
			return nil, fmt.Errorf("getting current Windows build: %w", err)
		}
	}

	allOpts := append([]Option{WithURL(url)}, opts...)
	client := NewWofaClient(allOpts...)

	root, err := client.DownloadFeed()
	if err != nil {
		return nil, nil
	}

	return buildUnpatchedCVEsOutput(root, deviceBuild, url), nil
}

func getCurrentWindowsBuild(socketPath string) (string, error) {
	client, err := osquery.NewClient(socketPath, 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("connecting to osquery: %w", err)
	}
	defer client.Close()

	resp, err := client.Query("SELECT version FROM os_version LIMIT 1")
	if err != nil {
		return "", fmt.Errorf("querying os_version: %w", err)
	}
	if resp.Status.Code != 0 {
		return "", fmt.Errorf("os_version query failed: %s", resp.Status.Message)
	}
	if len(resp.Response) == 0 {
		return "", fmt.Errorf("no rows returned from os_version")
	}

	return resp.Response[0]["version"], nil
}

// matchOSVersionForBuild finds the WOFA OSVersion whose releases share the same
// three-part build prefix as deviceBuild. For example, "10.0.26100" identifies
// all Windows 11 24H2 releases regardless of the patch revision.
func matchOSVersionForBuild(root *Root, deviceBuild string) *OSVersion {
	parts := strings.Split(deviceBuild, ".")
	if len(parts) < 3 {
		return nil
	}
	buildPrefix := strings.Join(parts[:3], ".") + "."

	for i := range root.OSVersions {
		for _, rel := range root.OSVersions[i].SecurityReleases {
			if strings.HasPrefix(rel.ProductVersion, buildPrefix) {
				return &root.OSVersions[i]
			}
		}
	}
	return nil
}

// revisionInt extracts the patch revision (4th component) from a Windows build
// string such as "10.0.26100.3476". Returns 0 for malformed strings.
func revisionInt(version string) int {
	parts := strings.Split(version, ".")
	if len(parts) < 4 {
		return 0
	}
	n, _ := strconv.Atoi(parts[3])
	return n
}

// buildUnpatchedCVEsOutput returns one row per actively-exploited CVE that
// appears in a security release with a revision number greater than the
// device's current revision. CVEs that appear in multiple releases are
// deduplicated — only the earliest release that patches the CVE is reported.
func buildUnpatchedCVEsOutput(root *Root, deviceBuild, url string) []map[string]string {
	osv := matchOSVersionForBuild(root, deviceBuild)
	if osv == nil {
		return nil
	}

	deviceRevision := revisionInt(deviceBuild)
	seen := make(map[string]bool)
	var results []map[string]string

	for _, rel := range osv.SecurityReleases {
		if revisionInt(rel.ProductVersion) <= deviceRevision {
			continue // device already has this patch or newer
		}
		for _, cveID := range rel.ActivelyExploitedCVEs {
			if seen[cveID] {
				continue
			}
			seen[cveID] = true

			row := map[string]string{
				"os_version":         osv.OSVersion,
				"cve_id":             cveID,
				"severity":           "",
				"cvss_score":         "",
				"in_kev":             "0",
				"patched_in_version": rel.ProductVersion,
				"nist_url":           "",
				"url":                url,
			}

			if detail, ok := rel.CVEs[cveID]; ok {
				row["severity"] = detail.Severity
				row["cvss_score"] = strconv.FormatFloat(detail.CVSSScore, 'f', 1, 64)
				if detail.InKEV {
					row["in_kev"] = "1"
				}
				row["nist_url"] = detail.NistURL
			}

			results = append(results, row)
		}
	}

	return results
}
