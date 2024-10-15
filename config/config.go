// SPDX-License-Identifier: MIT
//
// Configuration management.
//

package config

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"kexuedns/log"
)

const (
	configFilename = "config.json"
)

type Config struct {
	ConfigFile

	// Pool of trusted CAs parsed from CaFile.
	CaPool *x509.CertPool
}

type ConfigFile struct {
	// File containing the trusted CA certificates
	// (e.g., /etc/ssl/certs/ca-certificates.crt)
	// If empty, then use the system's trusted CA pool.
	CaFile string `json:"ca_file"`
	// The default resolver.
	Resolver *Resolver `json:"resolver"`
}

type Resolver struct {
	// IPv4 or IPv6 address
	IP string `json:"ip"`
	// DoT port; default 853
	Port int `json:"port"`
	// Hostname to verify the TLS certificate
	Hostname string `json:"hostname"`
}

var defaultConfigFile = ConfigFile{}

var config *Config
var configDir string

func Initialize(dir string) error {
	fp := filepath.Join(dir, configFilename)
	if _, err := os.Stat(fp); err == nil {
		log.Errorf("config file [%s] already exists", fp)
		return errors.New("file already exists")
	}

	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			log.Errorf("failed to create config dir [%s]: %v", dir, err)
			return err
		}
		log.Infof("created config dir: %s", dir)
	} else if err != nil {
		log.Errorf("cannot stat config dir [%s]: %v", dir, err)
		return err
	}

	data, err := json.MarshalIndent(&defaultConfigFile, "", "    ")
	if err != nil {
		panic(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(fp, data, 0644); err != nil {
		log.Errorf("failed to write config file [%s]: %v", fp, err)
		return err
	}
	log.Infof("created config file: %s", fp)

	return nil
}

func Load(dir string) error {
	conf := Config{}

	fp := filepath.Join(dir, configFilename)
	if data, err := os.ReadFile(fp); err == nil {
		if err := json.Unmarshal(data, &conf.ConfigFile); err != nil {
			log.Errorf("failed to load config from file [%s]: %v", fp, err)
			return err
		}
	} else if errors.Is(err, os.ErrNotExist) {
		conf.ConfigFile = defaultConfigFile
		log.Infof("config file [%s] doesn't exist; use the default", fp)
	} else {
		log.Errorf("failed to read config file [%s]: %v", fp, err)
		return err
	}

	if conf.CaFile != "" {
		certs, err := os.ReadFile(conf.CaFile)
		if err != nil {
			log.Errorf("failed to read file [%s]: %v", conf.CaFile, err)
			return err
		}
		conf.CaPool = x509.NewCertPool()
		if ok := conf.CaPool.AppendCertsFromPEM(certs); !ok {
			log.Errorf("failed to append CA certs from file: %s", conf.CaFile)
			return fmt.Errorf("invalid CA file: %s", conf.CaFile)
		}
		log.Infof("loaded CA certs from: %s", conf.CaFile)
	} else {
		var err error
		conf.CaPool, err = x509.SystemCertPool()
		if err != nil {
			log.Errorf("failed to get system cert pool: %v", err)
			return err
		}
		log.Infof("use system cert pool")
	}

	config = &conf
	configDir = dir
	log.Infof("loaded config from directory: %s", dir)

	return nil
}

func Get() *Config {
	if config == nil {
		panic("config is nil; Load() was not called or failed?")
	}
	return config
}

func Set(cf *ConfigFile) error {
	if config == nil {
		panic("config is nil; Load() was not called or failed?")
	}
	// TODO: update and write to file
	return nil
}
