// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 Aaron LI
//
// Configuration management - Version info
//

package config

type VersionInfo struct {
	Version string
	Date    string
}

var versionInfo VersionInfo

func GetVersion() *VersionInfo {
	return &versionInfo
}

func SetVersion(vi *VersionInfo) {
	versionInfo = *vi
}
