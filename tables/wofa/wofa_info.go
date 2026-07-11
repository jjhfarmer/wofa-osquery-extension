package wofa

import (
	"context"
	"strconv"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
)

// WofaSecurityReleaseInfoColumns defines the schema for the
// wofa_security_release_info table.
func WofaSecurityReleaseInfoColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("os_version"),
		table.TextColumn("update_name"),
		table.TextColumn("release_date"),
		table.TextColumn("product_version"),
		table.TextColumn("security_info"),
		table.IntegerColumn("unique_cves_count"),
		table.TextColumn("actively_exploited_cves"),
		table.IntegerColumn("days_since_previous_release"),
		table.TextColumn("supersedes"),
		table.IntegerColumn("patch_tuesday_release"),
		table.TextColumn("support_end_home_pro"),
		table.TextColumn("support_end_enterprise"),
		table.TextColumn("url"),
	}
}

// WofaSecurityReleaseInfoGenerate returns one row per OS version × security
// release. The feed URL and OS version can be overridden via WHERE clauses:
//
//	SELECT * FROM wofa_security_release_info WHERE os_version = 'Windows 11 24H2'
//	SELECT * FROM wofa_security_release_info WHERE url = 'https://mirror.example.com/feed.json'
//
// If the feed is unreachable the table returns empty rows rather than an error,
// so Fleet policies degrade gracefully on hosts without network access.
func WofaSecurityReleaseInfoGenerate(
	ctx context.Context,
	queryContext table.QueryContext,
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

	osVersionFilter := ""
	if cl, present := queryContext.Constraints["os_version"]; present {
		for _, c := range cl.Constraints {
			if c.Operator == table.OperatorEquals {
				osVersionFilter = c.Expression
			}
		}
	}

	allOpts := append([]Option{WithURL(url)}, opts...)
	client := NewWofaClient(allOpts...)

	root, err := client.DownloadFeed()
	if err != nil {
		// Return empty rows on network failure — table is best-effort.
		return nil, nil
	}

	return buildSecurityReleaseInfoOutput(root, osVersionFilter, url), nil
}

func buildSecurityReleaseInfoOutput(root *Root, osVersionFilter, url string) []map[string]string {
	var results []map[string]string

	for _, osv := range root.OSVersions {
		if osVersionFilter != "" && osv.OSVersion != osVersionFilter {
			continue
		}
		for _, rel := range osv.SecurityReleases {
			patchTuesdayInt := 0
			if rel.PatchTuesdayRelease {
				patchTuesdayInt = 1
			}
			results = append(results, map[string]string{
				"os_version":                  osv.OSVersion,
				"update_name":                 rel.UpdateName,
				"release_date":                rel.ReleaseDate,
				"product_version":             rel.ProductVersion,
				"security_info":               rel.SecurityInfo,
				"unique_cves_count":           strconv.Itoa(rel.UniqueCVEsCount),
				"actively_exploited_cves":     strings.Join(rel.ActivelyExploitedCVEs, ","),
				"days_since_previous_release": strconv.Itoa(rel.DaysSincePreviousRelease),
				"supersedes":                  rel.Supersedes,
				"patch_tuesday_release":       strconv.Itoa(patchTuesdayInt),
				"support_end_home_pro":        osv.SupportEndDate.HomePro,
				"support_end_enterprise":      osv.SupportEndDate.EnterpriseEducation,
				"url":                         url,
			})
		}
	}

	return results
}
