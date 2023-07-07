//go:build issuerconformance_test

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

package conformance

import (
	"flag"
	"fmt"
	"strings"
	"testing"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	ctrl "sigs.k8s.io/controller-runtime"

	"issuerconformance/certificates"
	"issuerconformance/certificatesigningrequests"
	"issuerconformance/framework/helper/featureset"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var namespace string
var unsupportedFeatures arrayFlags
var cmIssuerReferences arrayFlags
var k8sIssuerReferences arrayFlags

func init() {
	flag.StringVar(&namespace, "namespace", "", "list of issuer references to use for conformance tests")
	flag.Var(&unsupportedFeatures, "unsupported-features", "list of features that are not supported by this invocation of the test suite")
	flag.Var(&cmIssuerReferences, "cm-issuers", "list of issuer references to use for conformance tests")
	flag.Var(&k8sIssuerReferences, "k8s-issuers", "list of issuer references to use for conformance tests")
}

func parseCMReference(g *gomega.WithT, ref string) v1.ObjectReference {
	parts := strings.SplitN(ref, "/", 3)
	g.Expect(parts).To(gomega.HaveLen(3), "invalid issuer reference %q: expected format <group>/<kind>/<name>", ref)

	return v1.ObjectReference{
		Group: parts[0],
		Kind:  parts[1],
		Name:  parts[2],
	}
}

func TestConformance(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)

	g := gomega.NewGomegaWithT(t)

	restConfig, err := ctrl.GetConfig()
	g.Expect(err).To(gomega.BeNil(), "failed to get rest config", err)

	restConfig.Burst = 9000
	restConfig.QPS = 9000

	unsupportedFeatureSet := featureset.NewFeatureSet()

	for _, value := range unsupportedFeatures {
		feature, err := featureset.ConvertToFeature(value)
		g.Expect(err).To(gomega.BeNil(), "failed to convert unsupported feature %q: %v", value, err)
		unsupportedFeatureSet.Add(feature)
	}

	for _, ref := range cmIssuerReferences {
		(&certificates.Suite{
			KubeClientConfig:    restConfig,
			Name:                ref,
			Namespace:           namespace,
			IssuerRef:           parseCMReference(g, ref),
			UnsupportedFeatures: unsupportedFeatureSet,
		}).Define()
	}

	for _, ref := range k8sIssuerReferences {
		(&certificatesigningrequests.Suite{
			KubeClientConfig:    restConfig,
			Name:                ref,
			SignerName:          ref,
			UnsupportedFeatures: unsupportedFeatureSet,
		}).Define()
	}

	ginkgo.RunSpecs(t, "cert-manager conformance suite")
}
