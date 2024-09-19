// SPDX-License-Identifier: MIT
//
// Kexue DNS - DNS resovling in a scientific way.
//

package main

import (
	"flag"
	"fmt"
	"net/http"

	"kexuedns/log"
	"kexuedns/ui"
)

func main() {
	logLevel := flag.String("log-level", "info", "log level: debug/info/warn/error")
	httpAddr := flag.String("http-addr", "127.0.0.1", "HTTP webui address")
	httpPort := flag.Int("http-port", 8053, "HTTP webui port")
	flag.Parse()

	log.SetLevelString(*logLevel)
	log.Infof("set log level to [%s]", *logLevel)

	http.Handle("/static/", http.StripPrefix("/static/", ui.ServeStatic()))
	_ = ui.GetTemplate("xxx")

	httpListen := fmt.Sprintf("%s:%d", *httpAddr, *httpPort)
	log.Infof("HTTP webui: http://%s", httpListen)
	http.ListenAndServe(httpListen, nil)
}
