package wofa

import (
	"testing"
)

func TestRevisionInt(t *testing.T) {
	cases := []struct {
		input    string
		expected int
	}{
		{"10.0.26100.3476", 3476},
		{"10.0.19045.5487", 5487},
		{"10.0.26100", 0}, // fewer than 4 parts
		{"invalid", 0},
		{"", 0},
	}
	for _, tc := range cases {
		if got := revisionInt(tc.input); got != tc.expected {
			t.Errorf("revisionInt(%q) = %d, want %d", tc.input, got, tc.expected)
		}
	}
}

func TestMatchOSVersionForBuild(t *testing.T) {
	root := loadTestFeed(t)

	osv := matchOSVersionForBuild(root, "10.0.26100.3000")
	if osv == nil {
		t.Fatal("expected match for 10.0.26100.x, got nil")
	}
	if osv.OSVersion != "Windows 11 24H2" {
		t.Errorf("expected Windows 11 24H2, got %q", osv.OSVersion)
	}

	osv2 := matchOSVersionForBuild(root, "10.0.19045.5000")
	if osv2 == nil {
		t.Fatal("expected match for 10.0.19045.x, got nil")
	}
	if osv2.OSVersion != "Windows 10 22H2" {
		t.Errorf("expected Windows 10 22H2, got %q", osv2.OSVersion)
	}

	osv3 := matchOSVersionForBuild(root, "10.0.99999.1000")
	if osv3 != nil {
		t.Errorf("expected nil for unknown build prefix, got %q", osv3.OSVersion)
	}

	osv4 := matchOSVersionForBuild(root, "short")
	if osv4 != nil {
		t.Error("expected nil for malformed build string")
	}
}

func TestBuildUnpatchedCVEsOutput_DeviceBehind(t *testing.T) {
	root := loadTestFeed(t)
	// Device is at revision 3000; latest patch for Win11 24H2 is 3476
	rows := buildUnpatchedCVEsOutput(root, "10.0.26100.3000", "https://example.com/feed.json")
	if len(rows) != 2 {
		t.Fatalf("expected 2 unpatched CVEs, got %d", len(rows))
	}

	found := make(map[string]bool)
	for _, row := range rows {
		found[row["cve_id"]] = true
	}
	for _, cve := range []string{"CVE-2025-24985", "CVE-2025-24993"} {
		if !found[cve] {
			t.Errorf("expected %s in results", cve)
		}
	}
}

func TestBuildUnpatchedCVEsOutput_DeviceUpToDate(t *testing.T) {
	root := loadTestFeed(t)
	// Device is already at the latest revision
	rows := buildUnpatchedCVEsOutput(root, "10.0.26100.3476", "")
	if len(rows) != 0 {
		t.Errorf("expected 0 rows for up-to-date device, got %d", len(rows))
	}
}

func TestBuildUnpatchedCVEsOutput_InKEVAndSeverity(t *testing.T) {
	root := loadTestFeed(t)
	rows := buildUnpatchedCVEsOutput(root, "10.0.26100.3000", "")

	var kevRow map[string]string
	for _, row := range rows {
		if row["cve_id"] == "CVE-2025-24985" {
			kevRow = row
			break
		}
	}
	if kevRow == nil {
		t.Fatal("CVE-2025-24985 not found in results")
	}
	if kevRow["in_kev"] != "1" {
		t.Errorf("in_kev: got %q, want \"1\"", kevRow["in_kev"])
	}
	if kevRow["severity"] != "Important" {
		t.Errorf("severity: got %q, want \"Important\"", kevRow["severity"])
	}
	if kevRow["cvss_score"] != "7.8" {
		t.Errorf("cvss_score: got %q, want \"7.8\"", kevRow["cvss_score"])
	}
	if kevRow["patched_in_version"] != "10.0.26100.3476" {
		t.Errorf("patched_in_version: got %q", kevRow["patched_in_version"])
	}
}

func TestBuildUnpatchedCVEsOutput_NoCriticalKEV(t *testing.T) {
	root := loadTestFeed(t)
	rows := buildUnpatchedCVEsOutput(root, "10.0.26100.3000", "")

	var critRow map[string]string
	for _, row := range rows {
		if row["cve_id"] == "CVE-2025-24993" {
			critRow = row
			break
		}
	}
	if critRow == nil {
		t.Fatal("CVE-2025-24993 not found")
	}
	if critRow["in_kev"] != "0" {
		t.Errorf("in_kev: got %q, want \"0\" (not in CISA KEV)", critRow["in_kev"])
	}
	if critRow["severity"] != "Critical" {
		t.Errorf("severity: got %q", critRow["severity"])
	}
}

func TestBuildUnpatchedCVEsOutput_UnknownBuild(t *testing.T) {
	root := loadTestFeed(t)
	rows := buildUnpatchedCVEsOutput(root, "10.0.99999.1000", "")
	if rows != nil {
		t.Errorf("expected nil for unrecognised build, got %v", rows)
	}
}

func TestBuildUnpatchedCVEsOutput_NoDuplicateCVEs(t *testing.T) {
	// If a CVE appears in multiple releases, it should only be reported once.
	root := loadTestFeed(t)
	// Add the same CVE to a second release in Win11 24H2
	root.OSVersions[0].SecurityReleases[1].ActivelyExploitedCVEs = []string{"CVE-2025-24985"}
	root.OSVersions[0].SecurityReleases[1].CVEs = map[string]CVEDetail{
		"CVE-2025-24985": {Severity: "Important", CVSSScore: 7.8, ActivelyExploited: true, InKEV: true},
	}

	rows := buildUnpatchedCVEsOutput(root, "10.0.26100.3000", "")
	count := 0
	for _, row := range rows {
		if row["cve_id"] == "CVE-2025-24985" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("CVE-2025-24985 appeared %d times, expected 1", count)
	}
}
