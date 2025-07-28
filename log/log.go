// SPDX-License-Identifier: BSD-3-Clause
// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 Aaron LI
//
// Simple log facility.
//
// Derived from: https://github.com/DragonFlyBSD/mirrorselect (common/log.go)

package log

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	NoticeLevel
	WarnLevel
	ErrorLevel
)

func (l Level) String() string {
	switch l {
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case NoticeLevel:
		return "notice"
	case WarnLevel:
		return "warn"
	case ErrorLevel:
		return "error"
	default:
		return "(???)"
	}
}

var (
	level     Level
	outLogger *log.Logger
	errLogger *log.Logger
)

func init() {
	level = WarnLevel
	flag := log.Ldate | log.Ltime
	outLogger = log.New(os.Stdout, "", flag)
	errLogger = log.New(os.Stderr, "", flag)
}

func SetLevel(l Level) {
	level = l
}

func SetLevelString(l string) {
	l = strings.ToLower(l)
	switch l {
	case "error":
		level = ErrorLevel
	case "warn", "warning":
		level = WarnLevel
	case "notice":
		level = NoticeLevel
	case "info":
		level = InfoLevel
	case "debug":
		level = DebugLevel
	case "":
		break
	default:
		Warnf("unknown log level: %s", l)
	}
}

func Debugf(format string, v ...any) {
	if level > DebugLevel {
		return
	}
	format = fmt.Sprintf("[DEBUG] %s: %s\n", getOrigin(), format)
	errLogger.Printf(format, v...)
}

func Infof(format string, v ...any) {
	if level > InfoLevel {
		return
	}
	format = fmt.Sprintf("[INFO] %s: %s\n", getOrigin(), format)
	outLogger.Printf(format, v...)
}

func Noticef(format string, v ...any) {
	if level > NoticeLevel {
		return
	}
	format = fmt.Sprintf("[NOTICE] %s: %s\n", getOrigin(), format)
	outLogger.Printf(format, v...)
}

func Warnf(format string, v ...any) {
	if level > WarnLevel {
		return
	}
	format = fmt.Sprintf("[WARN] %s: %s\n", getOrigin(), format)
	errLogger.Printf(format, v...)
}

func Errorf(format string, v ...any) {
	format = fmt.Sprintf("[ERROR] %s: %s\n", getOrigin(), format)
	errLogger.Printf(format, v...)
}

func Fatalf(format string, v ...any) {
	format = fmt.Sprintf("[FATAL] %s: %s\n", getOrigin(), format)
	errLogger.Fatalf(format, v...)
}

// Get the file and function information of the logger caller.
// Result: "file:line:function"
func getOrigin() string {
	// calldepth is 2: caller -> logfunc() -> getOrigin()
	pc, file, line, ok := runtime.Caller(2)
	if !ok {
		return "???:?:???"
	}

	funcname := runtime.FuncForPC(pc).Name()
	fn := funcname[strings.LastIndex(funcname, ".")+1:]
	return file + ":" + strconv.Itoa(line) + ":" + fn
}
