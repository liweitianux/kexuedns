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

	"kexuedns/dns"
	"kexuedns/log"
	"kexuedns/ui"
)

var version string // set by build flags

func main() {
	logLevel := flag.String("log-level", "info", "log level: debug/info/warn/error")
	addr := flag.String("addr", "127.0.0.1", "DNS listening address")
	port := flag.Int("port", 5553, "DNS listening UDP port")
	httpAddr := flag.String("http-addr", "127.0.0.1", "HTTP webui address")
	httpPort := flag.Int("http-port", 8053, "HTTP webui port")
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("kexuedns %s\n", version)
		os.Exit(0)
	}

	log.SetLevelString(*logLevel)
	log.Infof("set log level to [%s]", *logLevel)

	go func() {
		listen := fmt.Sprintf("%s:%d", *addr, *port)
		log.Infof("DNS service (UDP): %s", listen)
		panic(dns.ListenAndServe(listen))
	}()

	http.Handle("/static/", http.StripPrefix("/static/", ui.ServeStatic()))
	_ = ui.GetTemplate("xxx")

	httpListen := fmt.Sprintf("%s:%d", *httpAddr, *httpPort)
	log.Infof("HTTP webui: http://%s", httpListen)
	http.ListenAndServe(httpListen, nil)
}
