#!/usr/bin/env bash
# Copyright 2021 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

if [[ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then # Running inside bazel
  echo "scraping release manifests..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel run //hack:scrape-release-manifests
  )
  exit 0
fi

out_dir="$BUILD_WORKSPACE_DIRECTORY/pkg/util/versionchecker/testfixtures"

mkdir -p $out_dir

cd $BUILD_WORKSPACE_DIRECTORY

for tag in $(git tag -l --sort=-creatordate --format='%(refname:short)' | sed -n '0,/v1.0.0-alpha.0/p') 
do
    if [ ! -f "$out_dir/$tag.yaml" ] && [ ! -f "$out_dir/$tag.notfound" ] && [ ! -f "$out_dir/$tag.err" ]; then
        HTTP_CODE=$(curl -Lo "$out_dir/$tag.yaml" --write-out "%{http_code}" https://github.com/jetstack/cert-manager/releases/download/$tag/cert-manager.yaml)
        if [[ ${HTTP_CODE} -lt 200 || ${HTTP_CODE} -gt 299 ]] ; then
            (mv "$out_dir/$tag.yaml" "$out_dir/$tag.notfound")
        fi
    fi
done
