#!/usr/bin/env bash
# Copyright 2020 The cert-manager Authors.
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
  echo "Updating generated clients..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel run //hack:scrape-release-notes
  )
  exit 0
fi

jq=$(realpath "$1")

out_dir="$BUILD_WORKSPACE_DIRECTORY/RELEASE_NOTES"

mkdir -p $out_dir

cd $BUILD_WORKSPACE_DIRECTORY

for tag in $(git tag) 
do
    if [ ! -f "$out_dir/$tag.md" ]; then
        curl --silent "https://api.github.com/repos/jetstack/cert-manager/releases/tags/$tag" | "$jq" -r ".body" > "$out_dir/$tag.md"
    fi
done
