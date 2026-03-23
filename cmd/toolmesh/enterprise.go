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

//go:build enterprise

package main

// Enterprise extensions are loaded via init() functions in the
// toolmesh-enterprise module. This file serves as documentation
// that ToolMesh supports build-tag-based extension loading.
//
// Build with: go build -tags enterprise ./cmd/toolmesh
//
// See: https://github.com/DunkelCloud/ToolMesh/blob/main/docs/architecture.md#extension-model
