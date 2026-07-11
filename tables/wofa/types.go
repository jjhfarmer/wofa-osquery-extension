package wofa

type Root struct {
	Version    string      `json:"Version"`
	UpdateHash string      `json:"UpdateHash"`
	LastCheck  string      `json:"LastCheck"`
	OSVersions []OSVersion `json:"OSVersions"`
}

type OSVersion struct {
	OSVersion        string            `json:"OSVersion"`
	SupportEndDate   SupportEndDate    `json:"SupportEndDate"`
	Latest           Latest            `json:"Latest"`
	SecurityReleases []SecurityRelease `json:"SecurityReleases"`
}

type SupportEndDate struct {
	HomePro             string `json:"HomePro"`
	EnterpriseEducation string `json:"EnterpriseEducation"`
}

type Latest struct {
	ReleaseDate           string   `json:"ReleaseDate"`
	ProductVersion        string   `json:"ProductVersion"`
	SecurityInfo          string   `json:"SecurityInfo"`
	UniqueCVEsCount       int      `json:"UniqueCVEsCount"`
	ActivelyExploitedCVEs []string `json:"ActivelyExploitedCVEs"`
}

type SecurityRelease struct {
	UpdateName               string               `json:"UpdateName"`
	ReleaseDate              string               `json:"ReleaseDate"`
	ProductVersion           string               `json:"ProductVersion"`
	SecurityInfo             string               `json:"SecurityInfo"`
	CVEs                     map[string]CVEDetail `json:"CVEs"`
	ActivelyExploitedCVEs    []string             `json:"ActivelyExploitedCVEs"`
	UniqueCVEsCount          int                  `json:"UniqueCVEsCount"`
	DaysSincePreviousRelease int                  `json:"DaysSincePreviousRelease"`
	Supersedes               string               `json:"Supersedes"`
	PatchTuesdayRelease      bool                 `json:"PatchTuesdayRelease"`
}

type CVEDetail struct {
	Severity          string  `json:"severity"`
	CVSSScore         float64 `json:"cvss_score"`
	ActivelyExploited bool    `json:"actively_exploited"`
	InKEV             bool    `json:"in_kev"`
	NistURL           string  `json:"nist_url"`
}
