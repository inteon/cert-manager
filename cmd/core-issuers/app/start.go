/*
Copyright 2023 The cert-manager Authors.

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

package app

import (
	"fmt"

	"github.com/spf13/cobra"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/cert-manager/cert-manager/core-issuers-binary/app/options"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

type CertManagerControllerOptions struct {
	ControllerOptions *options.ControllerOptions
}

func NewCertManagerControllerOptions() *CertManagerControllerOptions {
	o := &CertManagerControllerOptions{
		ControllerOptions: options.NewControllerOptions(),
	}

	return o
}

func NewCommandStartCoreIssuers(stopCh <-chan struct{}) *cobra.Command {
	o := NewCertManagerControllerOptions()

	cmd := &cobra.Command{
		Use:   "cert-manager-core-issuers",
		Short: fmt.Sprintf("cert-manager's 'core' issuers (%s) (%s)", util.AppVersion, util.AppGitCommit),
		Long: `
cert-manager is a Kubernetes addon to automate the management and issuance of
TLS certificates from various issuing sources.

The core-issuers component manages Issuer and ClusterIssuer resources, and the
various in-built issuers which those resources refer to.`,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Validate(args); err != nil {
				return fmt.Errorf("error validating options: %s", err)
			}

			logf.Log.V(logf.InfoLevel).Info("starting core-issuers", "version", util.AppVersion, "git-commit", util.AppGitCommit)
			if err := o.RunCertManagerController(stopCh); err != nil {
				cmd.SilenceUsage = true // Don't display usage information when exiting because of an error
				return err
			}

			return nil
		},
		SilenceErrors: true, // Errors are already logged when calling cmd.Execute()
	}

	flags := cmd.Flags()
	o.ControllerOptions.AddFlags(flags)
	utilfeature.DefaultMutableFeatureGate.AddFlag(flags)

	return cmd
}

func (o CertManagerControllerOptions) Validate(args []string) error {
	errors := []error{}
	errors = append(errors, o.ControllerOptions.Validate())
	return utilerrors.NewAggregate(errors)
}

func (o CertManagerControllerOptions) RunCertManagerController(stopCh <-chan struct{}) error {
	return Run(o.ControllerOptions, stopCh)
}
