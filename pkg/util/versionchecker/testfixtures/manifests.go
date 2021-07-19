/*
Copyright 2021 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testfixtures

import (
	"io/fs"
	"strings"
	"embed"
)

//go:embed *.yaml
var content embed.FS

func ListVersions() []string {
	items, _ := content.ReadDir(".")
	manifests := []string{}
	for _, item := range items {
		version := strings.TrimSuffix(item.Name(), ".yaml")

		manifests = append(manifests, version)
	}

	return manifests
}

func GetManifest(version string) (fs.File, error) {
	f, err := content.Open(version + ".yaml")
	if err != nil {
		return nil, err
	}
	return f, nil
}
