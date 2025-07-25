// SPDX-License-Identifier: MIT
//
// Kexue DNS - DNS resovling in a scientific way.
//

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"kexuedns/api"
	"kexuedns/config"
	"kexuedns/dns"
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

	conf := config.Get()
	addr := fmt.Sprintf("%s:%d", conf.ListenAddr, conf.ListenPort)
	forwarder := dns.NewForwarder(addr)

	go func() {
		if r := conf.Resolver; r != nil {
			resolver, err := dns.NewResolver(r.IP, r.Port, r.Hostname)
			if err != nil {
				log.Warnf("failed to create resolver with config: %+v, error: %v",
					r, err)
			} else {
				forwarder.SetResolver(resolver)
				log.Infof("added resolver: %+v", r)
			}
		}

		if err := forwarder.Serve(); err != nil {
			panic(err)
		}
	}()

	apiHandler := api.NewApiHandler(forwarder)

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
		log.Infof("enabled debug pprof at: http://%s:%d%s",
			*httpAddr, *httpPort, path)
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", *httpAddr, *httpPort),
		Handler: mux,
	}
	go func() {
		defer wg.Done()
		log.Infof("HTTP webui: http://%s", server.Addr)
		err := server.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("webui server failed: %v", err)
		}
	}()

	// Set up signal capturing.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	// Clean up.
	forwarder.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Errorf("failed to shutdown the webui server: %v", err)
	}

	wg.Wait()
	log.Infof("done; exiting")
}
