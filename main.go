// SPDX-License-Identifier: MIT
//
// Kexue DNS - DNS resovling in a scientific way.
//

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"kexuedns/config"
	"kexuedns/dns"
	"kexuedns/log"
	"kexuedns/ui"
)

const progname = "kexuedns"

var version string // set by build flags

func main() {
	logLevel := flag.String("log-level", "info", "log level: debug/info/notice/warn/error")
	configDir := flag.String("config-dir", "",
		fmt.Sprintf("config directory (default \"${XDG_CONFIG_HOME}/%s\")", progname))
	configInit := flag.Bool("config-init", false, "initialize with the default configs")
	addr := flag.String("addr", "127.0.0.1", "DNS listening address")
	port := flag.Int("port", 5553, "DNS listening UDP port")
	httpAddr := flag.String("http-addr", "127.0.0.1", "HTTP webui address")
	httpPort := flag.Int("http-port", 8053, "HTTP webui port")
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s %s\n", progname, version)
		os.Exit(0)
	}

	log.SetLevelString(*logLevel)
	log.Infof("set log level to [%s]", *logLevel)

	if *configDir == "" {
		if dir := os.Getenv("XDG_CONFIG_HOME"); dir == "" {
			fmt.Printf("ERROR: ${XDG_CONFIG_HOME} required but missing\n")
			os.Exit(1)
		} else {
			*configDir = filepath.Join(dir, progname)
			log.Infof("use default config directory: %s", *configDir)
		}
	}

	if *configInit {
		if err := config.Initialize(*configDir); err != nil {
			fmt.Printf("ERROR: failed to initialize config: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err := config.Load(*configDir); err != nil {
		fmt.Printf("ERROR: failed to load config: %v\n", err)
		os.Exit(1)
	}

	go func() {
		forwarder := dns.NewForwarder()

		conf := config.Get()
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

		listen := fmt.Sprintf("%s:%d", *addr, *port)
		log.Infof("DNS service (UDP): %s", listen)
		panic(forwarder.ListenAndServe(listen))
	}()

	http.Handle("/static/", http.StripPrefix("/static/", ui.ServeStatic()))
	_ = ui.GetTemplate("xxx")

	httpListen := fmt.Sprintf("%s:%d", *httpAddr, *httpPort)
	log.Infof("HTTP webui: http://%s", httpListen)
	http.ListenAndServe(httpListen, nil)
}
