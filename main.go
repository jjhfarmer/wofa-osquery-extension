package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/jjhfarmer/wofa-osquery-extension/tables/wofa"
	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

// Version is set at build time via -ldflags "-X main.Version=x.y.z".
var Version = "dev"

func main() {
	var (
		flSocketPath = flag.String("socket", "", "Path to the osquery socket")
		flTimeout    = flag.Int("timeout", 0, "Seconds to wait for osquery socket")
		_            = flag.Int("interval", 0, "")
		_            = flag.Bool("verbose", false, "")
	)
	flag.Parse()

	// Give osqueryd time to create the socket before we try to connect.
	time.Sleep(3 * time.Second)

	server, err := osquery.NewExtensionManagerServer(
		"wofa_extension",
		*flSocketPath,
		osquery.ServerTimeout(time.Duration(*flTimeout)*time.Second),
	)
	if err != nil {
		log.Fatalf("error creating extension manager: %s", err)
	}

	userAgent := wofa.BuildUserAgent(Version)
	wofaOpts := []wofa.Option{
		wofa.WithUserAgent(userAgent),
	}

	plugins := []osquery.OsqueryPlugin{
		table.NewPlugin(
			"wofa_security_release_info",
			wofa.WofaSecurityReleaseInfoColumns(),
			func(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
				return wofa.WofaSecurityReleaseInfoGenerate(ctx, qc, wofaOpts...)
			},
		),
		table.NewPlugin(
			"wofa_unpatched_cves",
			wofa.WofaUnpatchedCVEsColumns(),
			func(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
				return wofa.WofaUnpatchedCVEsGenerate(ctx, qc, *flSocketPath, wofaOpts...)
			},
		),
	}

	for _, p := range plugins {
		server.RegisterPlugin(p)
	}

	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
