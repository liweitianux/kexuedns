// SPDX-License-Identifier: MIT
//
// Configuration management.
//

package config

import (
	"crypto/x509"
	"fmt"
	"kexuedns/log"
	"os"
)

const (
	// File containing the trusted CA certificates
	CaFile = "/etc/ssl/certs/ca-certificates.crt"
)

var RootCAs *x509.CertPool

// TODO: Config struct ...
func Initialize() error {
	if CaFile != "" {
		certs, err := os.ReadFile(CaFile)
		if err != nil {
			log.Errorf("failed to read file (%s): %v", CaFile, err)
			return err
		}
		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM(certs); !ok {
			log.Errorf("failed to append CA certs from file: %s", CaFile)
			return fmt.Errorf("CA certs append failure")
		}
		RootCAs = certPool
		log.Infof("loaded CA certs from: %s", CaFile)
	} else {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			log.Errorf("failed to get system cert pool: %v", err)
			return err
		}
		RootCAs = certPool
		log.Infof("use system cert pool")
	}

	return nil
}
