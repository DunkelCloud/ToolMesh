// Copyright 2026 Dunkel Cloud GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sshcmd reads command files: YAML files in the pattern of a DADL
// that describe the commands a backend of transport ssh may run on a host.
//
// A command is a template, not a command line: a fixed argument vector with
// placeholders for typed parameters. The caller picks a command and fills in
// parameters; it never writes shell text. Every argument is quoted for the
// shell of the host, so a parameter value stays one argument whatever it
// contains, and the constraints of its parameter decide which values exist
// at all.
package sshcmd

import (
	"regexp"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// BackendType is the value of backend.type in a command file.
const BackendType = "ssh"

// Parameter types of a command.
const (
	TypeString  = "string"
	TypeInteger = "integer"
	TypeNumber  = "number"
	TypeBoolean = "boolean"
)

// HostParam is the name of the parameter with which a call selects the host
// of a backend that serves several. Commands cannot declare it.
const HostParam = "host"

// Limits and defaults of a command.
const (
	// DefaultTimeout bounds a command that sets no timeout.
	DefaultTimeout = 30 * time.Second
	// MaxTimeout is the longest timeout a command file may set.
	MaxTimeout = 10 * time.Minute
	// DefaultMaxOutput is how much of stdout and of stderr a result carries
	// when the command file sets no max_output.
	DefaultMaxOutput int64 = 128 << 10
	// MaxMaxOutput is the largest max_output a command file may set.
	MaxMaxOutput int64 = 4 << 20
	// DefaultMaxLength is the longest value, in bytes, a string parameter
	// takes when it sets no max_length.
	DefaultMaxLength = 1024
	// MaxMaxLength is the largest max_length a parameter may set.
	MaxMaxLength = 32 << 10
	// MaxCommandLength is the longest command line, in bytes, sent to a host.
	MaxCommandLength = 64 << 10
)

// file is the YAML shape of a command file.
type file struct {
	Backend backendDef `yaml:"backend"`
}

// backendDef is the backend block of a command file.
type backendDef struct {
	// Name is informational: the entry in backends.yaml names the backend.
	Name string `yaml:"name"`
	// Type must be BackendType.
	Type        string             `yaml:"type"`
	Description string             `yaml:"description"`
	Defaults    defaultsDef        `yaml:"defaults"`
	Tools       map[string]toolDef `yaml:"tools"`
}

// defaultsDef holds the settings commands inherit unless they set their own.
type defaultsDef struct {
	Timeout   string `yaml:"timeout"`
	MaxOutput string `yaml:"max_output"`
}

// toolDef is one command as written in the file.
type toolDef struct {
	Description string              `yaml:"description"`
	Access      string              `yaml:"access"`
	Argv        []string            `yaml:"argv"`
	Params      map[string]paramDef `yaml:"params"`
	Timeout     string              `yaml:"timeout"`
	MaxOutput   string              `yaml:"max_output"`
	// SuccessExitCodes lists the exit codes that are a result and no
	// failure; empty means 0 only.
	SuccessExitCodes []int `yaml:"success_exit_codes"`
}

// paramDef is one parameter as written in the file.
type paramDef struct {
	Type        string   `yaml:"type"`
	Required    *bool    `yaml:"required"`
	Default     any      `yaml:"default"`
	Description string   `yaml:"description"`
	Pattern     string   `yaml:"pattern"`
	Enum        []any    `yaml:"enum"`
	Min         *float64 `yaml:"min"`
	Max         *float64 `yaml:"max"`
	MaxLength   int      `yaml:"max_length"`
}

// Spec is a checked command file.
type Spec struct {
	// Name is the informational backend.name of the file; may be empty.
	Name string
	// Description says what the commands of the file are for.
	Description string
	// Tools are the commands by name.
	Tools map[string]*Tool
	// ContentHash is the hex-encoded SHA-256 digest of the file with CRLF
	// line endings normalized to LF.
	ContentHash string
}

// Tool is one command: a fixed argument vector with typed parameters.
type Tool struct {
	// Name is the command's name in the file.
	Name string
	// Description says what the command does.
	Description string
	// Access classifies the command for authorization and policies ("read",
	// "write", "admin", "dangerous" or a custom string). Never empty.
	Access string
	// Timeout bounds one run of the command.
	Timeout time.Duration
	// MaxOutput is how many bytes of stdout and of stderr a result carries.
	MaxOutput int64
	// Params are the command's parameters by name.
	Params map[string]*Param

	// argv is the argument vector; every element is a sequence of literal
	// text and parameter references and becomes exactly one argument.
	argv [][]segment
	// source is argv as the file writes it, for display.
	source []string
	// declared is Params in the form the generic argument check reads.
	declared map[string]dadl.ParamDef
	// successCodes are the exit codes that count as success.
	successCodes []int
}

// Param is one typed parameter of a command.
type Param struct {
	// Name is the parameter's name.
	Name string
	// Type is TypeString, TypeInteger, TypeNumber or TypeBoolean.
	Type string
	// Description documents the parameter for the caller.
	Description string
	// Default is the value of a call that leaves the parameter out; nil
	// when the parameter is required.
	Default any
	// Pattern is the regular expression a string value must match as a
	// whole; empty when Enum lists the values.
	Pattern string
	// Enum lists the only values the parameter takes, as the text the
	// command line carries; nil when any value within the other limits fits.
	Enum []string
	// Min and Max bound an integer or number parameter. Min is never nil
	// for those types: without a declared min it is 0, so that a value
	// cannot turn into an option by its sign.
	Min, Max *float64
	// MaxLength is the longest string value in bytes.
	MaxLength int

	pattern *regexp.Regexp
}

// segment is a piece of an argument: literal text, or the value of the
// parameter it names.
type segment struct {
	literal string
	param   string
}
