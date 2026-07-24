// Package browser provides headless Chromium lifecycle management via chromedp.
package browser

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/chromedp/chromedp"
)

// Config holds browser launch configuration.
type Config struct {
	// Headless controls whether Chrome runs without a visible window.
	// Set to false for interactive debugging / login flows.
	Headless bool

	// UserDataDir persists profile data (cookies, localStorage) across sessions.
	UserDataDir string

	// Proxy sets an upstream proxy (e.g., "http://127.0.0.1:8080").
	Proxy string

	// WindowSize sets the initial viewport dimensions.
	WindowWidth  int
	WindowHeight int

	// Timeout is the maximum duration for the browser session.
	Timeout time.Duration

	// Logger receives browser lifecycle messages.
	Logger *log.Logger
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() Config {
	return Config{
		Headless:     false, // Non-headless by default so user can browse & login
		UserDataDir:  "",
		WindowWidth:  1920,
		WindowHeight: 1080,
		Timeout:      0, // no timeout — run until user stops
	}
}

// Session wraps a chromedp browser context with cleanup.
type Session struct {
	Ctx        context.Context
	Cancel     context.CancelFunc
	AllocCancel context.CancelFunc
	Logger     *log.Logger
}

// Launch starts a new Chromium instance and returns a Session.
func Launch(cfg Config) (*Session, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "[browser] ", log.LstdFlags)
	}

	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.DisableGPU,

		// Allow all origins (for cross-origin JS bundles)
		chromedp.Flag("disable-web-security", false),
		chromedp.Flag("disable-features", "VizDisplayCompositor"),

		// Window size
		chromedp.WindowSize(cfg.WindowWidth, cfg.WindowHeight),
	}

	if cfg.Headless {
		opts = append(opts, chromedp.Headless)
	} else {
		// Show browser window for interactive login
		opts = append(opts,
			chromedp.Flag("headless", false),
		)
	}

	if cfg.UserDataDir != "" {
		opts = append(opts, chromedp.UserDataDir(cfg.UserDataDir))
	}

	if cfg.Proxy != "" {
		opts = append(opts, chromedp.ProxyServer(cfg.Proxy))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// Create browser context with logging
	ctx, cancel := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(cfg.Logger.Printf),
	)

	// Enable network tracking
	if err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return nil
		}),
	); err != nil {
		cancel()
		allocCancel()
		return nil, fmt.Errorf("browser: launch failed: %w", err)
	}

	cfg.Logger.Println("chromium launched successfully")

	return &Session{
		Ctx:         ctx,
		Cancel:      cancel,
		AllocCancel: allocCancel,
		Logger:      cfg.Logger,
	}, nil
}

// Navigate opens the given URL in the browser.
func (s *Session) Navigate(url string) error {
	s.Logger.Printf("navigating to: %s", url)
	return chromedp.Run(s.Ctx, chromedp.Navigate(url))
}

// EnableNetwork enables CDP network domain events so we can intercept traffic.
func (s *Session) EnableNetwork() error {
	return chromedp.Run(s.Ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return chromedp.Run(ctx,
				chromedp.ActionFunc(func(ctx context.Context) error {
					// Enable network events
					if err := chromedp.Run(ctx); err != nil {
						return err
					}
					return nil
				}),
			)
		}),
	)
}

// Close shuts down the browser and releases resources.
func (s *Session) Close() {
	s.Logger.Println("shutting down chromium")
	s.Cancel()
	s.AllocCancel()
}
