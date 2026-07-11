package wofa

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const WofaV1URL = "https://wofa.dev/v1/windows_data_feed.json"

type Option func(*WofaClient)

// WofaClient fetches and decodes the WOFA security feed.
type WofaClient struct {
	endpoint   string
	httpClient *http.Client
	userAgent  string
}

func WithURL(url string) Option {
	return func(c *WofaClient) {
		c.endpoint = url
	}
}

func WithUserAgent(ua string) Option {
	return func(c *WofaClient) {
		c.userAgent = ua
	}
}

func NewWofaClient(opts ...Option) *WofaClient {
	c := &WofaClient{
		endpoint: WofaV1URL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		userAgent: "wofa-osquery-extension",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// BuildUserAgent returns a versioned User-Agent string for use in main.
func BuildUserAgent(version string) string {
	return fmt.Sprintf("wofa-osquery-extension/%s", version)
}

// DownloadFeed fetches and decodes the full WOFA JSON feed.
func (c *WofaClient) DownloadFeed() (*Root, error) {
	req, err := http.NewRequest(http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP %d from WOFA feed", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("creating gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	var root Root
	if err := json.NewDecoder(reader).Decode(&root); err != nil {
		return nil, fmt.Errorf("parsing feed JSON: %w", err)
	}

	return &root, nil
}
