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

package version

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	"github.com/jetstack/cert-manager/pkg/util/versionchecker"
)

// Options is a struct to support check api command
type Options struct {
	VersionChecker versionchecker.Interface

	// Is `true` if we should use provided namespace instead of guessed namespace
	NamespaceOverrides bool

	// Namespace of cert-manager installation
	Namespace string

	genericclioptions.IOStreams
}

// TODO: fix this explanation
var checkVersionDesc = templates.LongDesc(i18n.T(`
This check tries to find the version of the currently installed cert-manager installation.
"apiextensions.k8s.io/v1beta1" cert-manager crds, these were used until
cert-manager v1.0.0-alpha.0 and all should have a "helm.sh/chart" label containing the version.
Starting from version v1.0.0-alpha.1 "apiextensions.k8s.io/v1" crd resources are used, this
check looks for a "app.kubernetes.io/name" or "helm.sh/chart" label to determine the version.
If non of these labels are present, we try to determine the verion by looking at the conversion
webhook linked to the CRD to determine the correct cert-manager namespace and derive the version
via the tag of the image of that webhook.
`))

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete(factory cmdutil.Factory) error {
	var err error

	o.Namespace, o.NamespaceOverrides, err = factory.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return fmt.Errorf("Error: cannot get the namespace: %v", err)
	}

	restConfig, err := factory.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("Error: cannot create the REST config: %v", err)
	}

	o.VersionChecker, err = versionchecker.New(restConfig, scheme.Scheme)
	if err != nil {
		return fmt.Errorf("Error: %v", err)
	}

	return nil
}

// NewCmdCheckVersion returns a cobra command for checking the cert-manager version
func NewCmdCheckVersion(ctx context.Context, ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use:   "version",
		Short: "This check attempts to determine the version of the cert-manager installation",
		Long:  checkVersionDesc,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Complete(factory); err != nil {
				return err
			}
			return o.Run(ctx)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	return cmd
}

// Run executes check api command
func (o *Options) Run(ctx context.Context) error {
	version, err := o.VersionChecker.Version(ctx)
	if err != nil {
		return fmt.Errorf("Error: %v", err)
	}

	fmt.Fprintln(o.Out, version)

	return nil
}
