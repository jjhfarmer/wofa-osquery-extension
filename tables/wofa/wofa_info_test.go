package wofa

import (
	_ "embed"
	"encoding/json"
	"testing"
)

//go:embed test_data.json
var testFeedData []byte

func loadTestFeed(t *testing.T) *Root {
	t.Helper()
	var root Root
	if err := json.Unmarshal(testFeedData, &root); err != nil {
		t.Fatalf("failed to parse test fixture: %v", err)
	}
	return &root
}

func TestBuildSecurityReleaseInfoOutput_AllVersions(t *testing.T) {
	root := loadTestFeed(t)
	rows := buildSecurityReleaseInfoOutput(root, "", "https://example.com/feed.json")
	// fixture: Win11 24H2 has 2 releases, Win10 22H2 has 1 → 3 rows total
	if len(rows) != 3 {
		t.Errorf("expected 3 rows, got %d", len(rows))
	}
}

func TestBuildSecurityReleaseInfoOutput_FilterByVersion(t *testing.T) {
	root := loadTestFeed(t)
	rows := buildSecurityReleaseInfoOutput(root, "Windows 11 24H2", "")
	if len(rows) != 2 {
		t.Errorf("expected 2 rows for Windows 11 24H2, got %d", len(rows))
	}
	for _, row := range rows {
		if row["os_version"] != "Windows 11 24H2" {
			t.Errorf("unexpected os_version %q", row["os_version"])
		}
	}
}

func TestBuildSecurityReleaseInfoOutput_Fields(t *testing.T) {
	root := loadTestFeed(t)
	rows := buildSecurityReleaseInfoOutput(root, "Windows 11 24H2", "https://example.com/feed.json")
	if len(rows) == 0 {
		t.Fatal("expected rows, got none")
	}
	row := rows[0]

	if got := row["update_name"]; got != "2025-03 Cumulative Update for Windows 11 (KB5053598)" {
		t.Errorf("update_name: got %q", got)
	}
	if got := row["product_version"]; got != "10.0.26100.3476" {
		t.Errorf("product_version: got %q", got)
	}
	if got := row["unique_cves_count"]; got != "41" {
		t.Errorf("unique_cves_count: got %q", got)
	}
	if got := row["patch_tuesday_release"]; got != "1" {
		t.Errorf("patch_tuesday_release: got %q", got)
	}
	if got := row["support_end_home_pro"]; got != "2026-10-13" {
		t.Errorf("support_end_home_pro: got %q", got)
	}
	// actively_exploited_cves should be comma-separated
	exploited := row["actively_exploited_cves"]
	if exploited == "" {
		t.Error("actively_exploited_cves should not be empty")
	}
}

func TestBuildSecurityReleaseInfoOutput_NoMatchFilter(t *testing.T) {
	root := loadTestFeed(t)
	rows := buildSecurityReleaseInfoOutput(root, "Windows 11 23H2", "")
	if len(rows) != 0 {
		t.Errorf("expected 0 rows for unknown OS version, got %d", len(rows))
	}
}

func TestBuildSecurityReleaseInfoOutput_EmptyFeed(t *testing.T) {
	root := &Root{}
	rows := buildSecurityReleaseInfoOutput(root, "", "")
	if len(rows) != 0 {
		t.Errorf("expected 0 rows for empty feed, got %d", len(rows))
	}
}
