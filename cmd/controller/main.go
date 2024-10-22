/*
Copyright 2020 The cert-manager Authors.

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

package main

import (
	"flag"

	"github.com/controller-funtime/base/cmdutil"
	"github.com/controller-funtime/base/logs"

	"github.com/cert-manager/cert-manager/controller-binary/app"
	"github.com/cert-manager/cert-manager/internal/cmd/util"
)

func main() {
	ctx, exit := cmdutil.SetupExitHandler(cmdutil.GracefulShutdown)
	defer exit() // This function might call os.Exit, so defer last.

	ctx, cancel := logs.SetupLogger(ctx)
	defer cancel() // This function will stop flushing the logs.

	ctx = logs.WithValue(ctx, logs.FromContext(ctx).WithName("controller"))

	cmd := app.NewServerCommand(ctx)
	cmd.Flags().AddGoFlagSet(flag.CommandLine)

	if err := cmd.ExecuteContext(ctx); err != nil {
		logs.FromContext(ctx).Error(err, "error executing command")
		util.SetExitCode(err)
	}
}
