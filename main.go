// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// Kexue DNS - DNS resovling in a scientific way.
//

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"kexuedns/api"
	"kexuedns/config"
	"kexuedns/log"
	"kexuedns/ui"
)

const progname = "KexueDNS"

var (
	// set by build flags
	version     string
	versionDate string
)

func main() {
	isDebug := flag.Bool("debug", false, "enable debug profiling")
	logLevel := flag.String("log-level", "info", "log level: debug/info/notice/warn/error")
	configDir := flag.String("config-dir", "",
		fmt.Sprintf("config directory (default \"${XDG_CONFIG_HOME}/%s\")",
			strings.ToLower(progname)))
	configInit := flag.Bool("config-init", false, "initialize with the default configs")
	httpAddr := flag.String("http-addr", "127.0.0.1", "HTTP webui address")
	httpPort := flag.Uint("http-port", 5580, "HTTP webui port")
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s %s (%s)\n", progname, version, versionDate)
		return
	}

	config.SetVersion(&config.VersionInfo{
		Version: version,
		Date:    versionDate,
	})

	log.SetLevelString(*logLevel)
	log.Infof("set log level to [%s]", *logLevel)

	if *configDir == "" {
		if dir := os.Getenv("XDG_CONFIG_HOME"); dir == "" {
			fmt.Printf("ERROR: ${XDG_CONFIG_HOME} required but missing\n")
			os.Exit(1)
		} else {
			*configDir = filepath.Join(dir, strings.ToLower(progname))
			log.Infof("use default config directory: %s", *configDir)
		}
	}

	if *configInit {
		if err := config.Initialize(*configDir); err != nil {
			fmt.Printf("ERROR: failed to initialize config: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := config.Load(*configDir); err != nil {
		fmt.Printf("ERROR: failed to load config: %v\n", err)
		os.Exit(1)
	}

	addr, err := netip.ParseAddr(*httpAddr)
	if err != nil {
		log.Fatalf("invalid http-addr: %s, error: %v", *httpAddr, err)
	}

	addrport := netip.AddrPortFrom(addr, uint16(*httpPort))
	baseURL := "http://" + addrport.String()
	if addr.IsUnspecified() {
		log.Warnf("webui server is public accessible! (addr=%s)", addr.String())

		addr := addr
		if addr.Is4() {
			addr = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		} else {
			addr = netip.IPv6Loopback()
		}
		baseURL = "http://" + netip.AddrPortFrom(addr, uint16(*httpPort)).String()
	}

	apiHandler := api.NewApiHandler()

	mux := http.NewServeMux()
	mux.Handle("/api/", http.StripPrefix("/api", apiHandler))
	mux.Handle("/static/", http.StripPrefix("/static/", ui.ServeStatic()))
	mux.HandleFunc("GET /{$}", ui.ServeIndex) // NOTE: Require Go 1.22+

	if *isDebug {
		path := "/debug/pprof/"
		mux.HandleFunc(path, pprof.Index)
		mux.HandleFunc(path+"cmdline", pprof.Cmdline)
		mux.HandleFunc(path+"profile", pprof.Profile)
		mux.HandleFunc(path+"symbol", pprof.Symbol)
		mux.HandleFunc(path+"trace", pprof.Trace)
		log.Infof("enabled debug pprof at: %s%s", baseURL, path)
	}

	listener, err := net.Listen("tcp", addrport.String())
	if err != nil {
		log.Fatalf("failed to listen at: %s, error: %v", addrport.String(), err)
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	server := &http.Server{Handler: mux}
	go func() {
		defer wg.Done()
		log.Infof("access webui: %s", baseURL)
		err := server.Serve(listener)
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("webui server failed: %v", err)
		}
	}()

	// Start the forwarder.
	// Do this after listen, so this request would wait for the server to
	// accept instead of simply failing if it races aganist the server listen.
	resp, err := http.Post(baseURL+"/api/start", "", nil)
	if err != nil {
		log.Warnf("failed to request: %v", err)
	} else {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			log.Warnf("failed to start forwarder: %s", body)
		}
	}

	// Set up signal capturing.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	// Clean up.
	_, _ = http.Post(baseURL+"/api/stop", "", nil)
	if err := server.Close(); err != nil {
		log.Errorf("failed to close the webui server: %v", err)
	}

	wg.Wait()
	log.Infof("done; exiting")
}
