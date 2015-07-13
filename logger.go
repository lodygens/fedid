package main

/*
 Copyrights     : CNRS
 Author         : Oleg Lodygensky

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License.  You may
obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.  See the License for the specific language governing
permissions and limitations under the License.

*/

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

type LoggerLevel uint

func (a LoggerLevel) ToString() string {
	return fmt.Sprintf("%v", a)
}

const (
	FINEST = iota
	DEBUG
	CONFIG
	INFO
	WARN
	ERROR
	FATAL
	StdLevel = DEBUG // initial values for the standard logger
)

var loggerLevel LoggerLevel = StdLevel
// SetLevel sets the logger level
func SetLoggerLevel(str string) {
	loggerLevel = DEBUG
	str = strings.ToUpper(str)
	switch str {
		case "FINEST":
		loggerLevel = FINEST
		return
		case "DEBUG":
		loggerLevel = DEBUG
		return
		case "CONFIG":
		loggerLevel = CONFIG 
		return
		case "INFO":
		loggerLevel = INFO 
		return
		case "WARN":
		loggerLevel = WARN 
		return
		case "ERROR":
		loggerLevel = ERROR 
		return
		case "FATAL":
		loggerLevel = FATAL
		return
	}
}

type LeveledLogger struct {
	logger log.Logger
	level  LoggerLevel
}

// New creates a new Logger.   The out variable sets the
// destination to which log data will be written.
// The prefix appears at the beginning of each generated log line.
// The flag argument defines the logging properties.
func New(out io.Writer, prefix string, flag int, l LoggerLevel) *LeveledLogger {
	return &LeveledLogger{logger: *log.New(out, prefix, flag), level: l}
}

// NewDefault calls New(os.Stderr, "", log.LstdFlags, loggerLevel)
func NewDefault() *LeveledLogger {
	return New(os.Stderr, "", log.LstdFlags, loggerLevel)
}

// NewLeveled calls New(os.Stderr, "", log.LstdFlags, l)
func NewLeveled(l LoggerLevel) *LeveledLogger {
	return New(os.Stderr, "", log.LstdFlags, l)
}

// NewPrefixed calls New(os.Stderr, prefix, log.LstdFlags, loggerLevel)
func NewPrefixed(prefix string) *LeveledLogger {
	return New(os.Stderr, prefix+" ", log.LstdFlags, loggerLevel)
}

// SetLevel sets the logger level
func (log *LeveledLogger) SetLevel(l LoggerLevel) {
	if l > FATAL {
		l = FATAL
	}
	log.level = l
}

// SetPrefix sets the output prefix for the logger.
func (log *LeveledLogger) SetPrefix(p string) {
	log.logger.SetPrefix(p)
}

// IsFinest tests if level is FINEST
// @return true if level is lower or equal to FINEST
func (log *LeveledLogger) IsFinest() bool {
	return log.level <= FINEST
}

// Finest calls log.logger.Printf(format, v) if level is FINEST.
// This does nothing otherwise
// @see IsFinest()
func (log *LeveledLogger) Finest(format string, v ...interface{}) {
	if log.IsFinest() {
		log.logger.Printf("FINEST : "+format, v...)
	}
}

// IsDebug tests if level is DEBUG
// @return true if level is lower or equal to DEBUG
func (log *LeveledLogger) IsDebug() bool {
	return log.level <= DEBUG
}

// Debug calls log.logger.Printf(format, v) if level is DEBUG.
// This does nothing otherwise
// @see IsDebug()
func (log *LeveledLogger) Debug(format string, v ...interface{}) {
	if log.IsDebug() {
		log.logger.Printf("DEBUG : "+format, v...)
	}
}

// IsConfig tests if level is CONFIG
// @return true if level is lower or equal to CONFIG
func (log *LeveledLogger) IsConfig() bool {
	return log.level <= CONFIG
}

// Config calls log.logger.Printf(format, v) if level is CONFIG.
// This does nothing otherwise
// @see IsConfig()
func (log *LeveledLogger) Config(format string, v ...interface{}) {
	if log.IsConfig() {
		log.logger.Printf("CONFIG : "+format, v...)
	}
}

// IsInfo tests if level is INFO
// @return true if level is lower or equal to INFO
func (log *LeveledLogger) IsInfo() bool {
	return log.level <= INFO
}

// Info calls log.logger.Printf(format, v) if level is INFO.
// This does nothing otherwise
// @see IsInfo()
func (log *LeveledLogger) Info(format string, v ...interface{}) {
	if log.IsInfo() {
		log.logger.Printf("INFO : "+format, v...)
	}
}

// IsWarn tests if level is WARN
// @return true if level is lower or equal to WARN
func (log *LeveledLogger) IsWarn() bool {
	return log.level <= WARN
}

// Warn calls log.logger.Printf(format, v) if level is WARN.
// This does nothing otherwise
// @see IsWarn()
func (log *LeveledLogger) Warn(format string, v ...interface{}) {
	if log.IsWarn() {
		log.logger.Printf("WARN : "+format, v...)
	}
}

// IsError tests if level is ERROR
// @return true if level is lower or equal to ERROR
func (log *LeveledLogger) IsError() bool {
	return log.level <= ERROR
}

// Error calls log.logger.Printf(format, v) if level is ERROR.
// This does nothing otherwise
// @see IsError()
func (log *LeveledLogger) Error(format string, v ...interface{}) {
	if log.IsError() {
		log.logger.Printf("ERROR : "+format, v...)
	}
}

// IsFatal tests if level is FATAL
// @return true if level is lower or equal to FATAL
func (log *LeveledLogger) IsFatal() bool {
	return log.level <= FATAL
}

// Fatal calls log.logger.Printf(format, v) if level is FATAL
// This does nothing otherwise
// @see IsFatal()
func (log *LeveledLogger) Fatal(format string, v ...interface{}) {
	if log.IsFatal() {
		log.logger.Fatalf("FATAL : "+format, v...)
	}
}
