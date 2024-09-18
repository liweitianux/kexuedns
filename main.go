// SPDX-License-Identifier: MIT
//
// Kexue DNS - DNS resovling in a scientific way.
//

package main

import (
	"flag"

	"kexuedns/log"
)

func main() {
	logLevel := flag.String("log-level", "info", "log level: debug/info/warn/error")
	flag.Parse()

	log.SetLevelString(*logLevel)
	log.Infof("set log level to [%s]", *logLevel)
}
