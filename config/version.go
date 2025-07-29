// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// Configuration management - Version info
//

package config

// set by build flags
var (
	version     = "???"
	versionDate = "???"
)

type VersionInfo struct {
	Version string
	Date    string
}

func GetVersion() *VersionInfo {
	return &VersionInfo{
		Version: version,
		Date:    versionDate,
	}
}
