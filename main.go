// graphoper — Passive GraphQL reconnaissance tool.
//
// Launches a Chromium browser, observes all network traffic during normal
// browsing, captures GraphQL operations and responses, downloads JS bundles,
// extracts embedded GraphQL queries, deduplicates everything, and stores
// results in SQLite for later analysis.
//
// Usage:
//
//	graphoper [flags] <url>
//
// Flags:
//
//	-headless        Run Chromium in headless mode (default: false)
//	-profile <dir>   Persist browser profile to <dir> for session reuse
//	-proxy <url>     Route traffic through an HTTP proxy
//	-db <path>       SQLite database path (default: database/graphoper.db)
//	-bundles <dir>   Directory for downloaded JS bundles (default: bundles/)
//	-timeout <dur>   Maximum session duration (default: 0 = unlimited)
//	-v               Verbose logging
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/the5orcerer/graphoper/internal/browser"
	"github.com/the5orcerer/graphoper/internal/capture"
	"github.com/the5orcerer/graphoper/internal/dedup"
	"github.com/the5orcerer/graphoper/internal/storage"
)

const banner = `
   ╔══════════════════════════════════════════╗
   ║         ┏━┓┏━┓┏━┓┏━┓┏┓ ┏┓┏━┓┏━┓┏━┓     ║
   ║         ┃╻┃┃┏┛┃┃┃┃╻┃┃┗┓┃┃┃╻┃┃╻┃┃┏┛     ║
   ║         ┗━┛┗┛ ┗━┛┗━┛┗━┛┗┛┗━┛┣━┛┗┛      ║
   ║              GraphQL Recon    ┃          ║
   ║         Passive · Observe · Store        ║
   ╚══════════════════════════════════════════╝
`

func main() {
	// ── Flags ──
	var (
		headless   = flag.Bool("headless", false, "Run Chromium in headless mode")
		profile    = flag.String("profile", "", "Browser profile directory for session persistence")
		proxy      = flag.String("proxy", "", "HTTP proxy URL (e.g., http://127.0.0.1:8080)")
		dbPath     = flag.String("db", "database/graphoper.db", "SQLite database path")
		bundleDir  = flag.String("bundles", "bundles", "JS bundle download directory")
		timeout    = flag.Duration("timeout", 0, "Max session duration (0 = unlimited)")
		verbose    = flag.Bool("v", false, "Verbose logging")
	)
	flag.Parse()

	fmt.Print(banner)

	// ── Logger ──
	logFlags := log.LstdFlags | log.Lmicroseconds
	logger := log.New(os.Stdout, "", logFlags)

	if !*verbose {
		// In non-verbose mode, suppress debug-level output
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	// Setup log file
	if err := os.MkdirAll("logs", 0o755); err != nil {
		logger.Fatalf("failed to create logs dir: %v", err)
	}
	logFile, err := os.OpenFile(
		filepath.Join("logs", fmt.Sprintf("session_%s.log", time.Now().Format("20060102_150405"))),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644,
	)
	if err != nil {
		logger.Fatalf("failed to create log file: %v", err)
	}
	defer logFile.Close()

	// Tee to both stdout and file
	fileLogger := log.New(logFile, "", log.LstdFlags|log.Lmicroseconds)

	logBoth := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		logger.Print(msg)
		fileLogger.Print(msg)
	}

	// ── Target URL ──
	targetURL := ""
	if flag.NArg() > 0 {
		targetURL = flag.Arg(0)
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			targetURL = "https://" + targetURL
		}
	}

	// ── Storage ──
	logBoth("[init] opening database: %s", *dbPath)
	db, err := storage.New(*dbPath)
	if err != nil {
		logger.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// ── Bundle dir ──
	if err := os.MkdirAll(*bundleDir, 0o755); err != nil {
		logger.Fatalf("failed to create bundle dir: %v", err)
	}

	// ── Deduplicator ──
	dd := dedup.New()

	// ── Browser ──
	cfg := browser.Config{
		Headless:     *headless,
		UserDataDir:  *profile,
		Proxy:        *proxy,
		WindowWidth:  1920,
		WindowHeight: 1080,
		Timeout:      *timeout,
		Logger:       log.New(os.Stdout, "[browser] ", log.LstdFlags),
	}

	logBoth("[init] launching chromium (headless=%v)", *headless)
	session, err := browser.Launch(cfg)
	if err != nil {
		logger.Fatalf("failed to launch browser: %v", err)
	}
	defer session.Close()

	// ── Enable Network domain ──
	if err := chromedp.Run(session.Ctx,
		network.Enable(),
	); err != nil {
		logger.Fatalf("failed to enable network events: %v", err)
	}
	logBoth("[init] network event capture enabled")

	// ── Capturer ──
	capturer := capture.New(db, dd, *bundleDir, log.New(os.Stdout, "", log.LstdFlags))
	capturer.SetupListeners(session.Ctx)
	logBoth("[init] event listeners registered")

	// ── Navigate to target ──
	if targetURL != "" {
		logBoth("[nav] opening: %s", targetURL)
		if err := session.Navigate(targetURL); err != nil {
			logger.Fatalf("failed to navigate: %v", err)
		}
		logBoth("[nav] page loaded")
	} else {
		logBoth("[init] no target URL specified — browse to any page in the browser window")
		// Navigate to a blank page to start
		if err := chromedp.Run(session.Ctx, chromedp.Navigate("about:blank")); err != nil {
			logger.Fatalf("failed to open blank page: %v", err)
		}
	}

	// ── Status ticker ──
	statusTicker := time.NewTicker(15 * time.Second)
	defer statusTicker.Stop()

	go func() {
		for range statusTicker.C {
			reqs, gql, bundles := capturer.Stats()
			ops, resps, bndls, frags, _ := db.Stats()
			logBoth("[status] requests=%d graphql=%d bundles_dl=%d | db: ops=%d resps=%d bundles=%d types=%d",
				reqs, gql, bundles, ops, resps, bndls, frags)
		}
	}()

	// ── Wait for shutdown ──
	logBoth("[ready] graphoper is running — browse normally, all GraphQL traffic is being captured")
	logBoth("[ready] press Ctrl+C to stop and save")

	ctx := session.Ctx
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	// Wait for Ctrl+C or timeout
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logBoth("\n[shutdown] received signal: %v", sig)
	case <-ctx.Done():
		logBoth("\n[shutdown] session ended")
	}

	// ── Final stats ──
	reqs, gql, bundles := capturer.Stats()
	ops, resps, bndls, frags, _ := db.Stats()
	logBoth("[final] ═══════════════════════════════════════")
	logBoth("[final] Total requests observed:  %d", reqs)
	logBoth("[final] GraphQL operations found: %d", gql)
	logBoth("[final] JS bundles downloaded:    %d", bundles)
	logBoth("[final] ───────────────────────────────────────")
	logBoth("[final] DB operations:     %d", ops)
	logBoth("[final] DB responses:      %d", resps)
	logBoth("[final] DB bundles:        %d", bndls)
	logBoth("[final] DB schema types:   %d", frags)
	logBoth("[final] Unique op hashes:  %d", dd.Count())
	logBoth("[final] ═══════════════════════════════════════")
	logBoth("[final] database saved: %s", *dbPath)
	logBoth("[final] session complete")
}
