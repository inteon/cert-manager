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

package external

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"issuerconformance/certificates"
	"issuerconformance/framework/helper/featureset"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

const (
	sampleExternalIssuerNamespace = "sample-external-issuer-system"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	frwork := framework.NewDefaultFramework("ca-certificates")

	unsupportedFeatures := featureset.NewFeatureSet(
		featureset.DurationFeature,
		featureset.KeyUsagesFeature,
		featureset.SaveCAToSecret,
		featureset.Ed25519FeatureSet,
		featureset.IssueCAFeature,
		featureset.LiteralSubjectFeature,
	)

	{
		issuer := newIssuerBuilder("Issuer", false)
		(&certificates.Suite{
			Name: "External Issuer",
			CompleteHook: func(ctx context.Context, s *certificates.Suite) {
				s.KubeClientConfig = frwork.KubeClientConfig
				s.Namespace = frwork.Namespace.Name
				issuer.createIssuer(ctx, frwork)
				s.IssuerRef = issuer.IssuerRef

				DeferCleanup(func(ctx context.Context) {
					issuer.deleteIssuer(ctx, frwork)
				})
			},
			UnsupportedFeatures: unsupportedFeatures,
		}).Define()
	}

	{
		issuer := newIssuerBuilder("ClusterIssuer", true)
		(&certificates.Suite{
			Name: "External ClusterIssuer",
			CompleteHook: func(ctx context.Context, s *certificates.Suite) {
				s.KubeClientConfig = frwork.KubeClientConfig
				s.Namespace = frwork.Namespace.Name
				issuer.createIssuer(ctx, frwork)
				s.IssuerRef = issuer.IssuerRef

				DeferCleanup(func(ctx context.Context) {
					issuer.deleteIssuer(ctx, frwork)
				})
			},
			UnsupportedFeatures: unsupportedFeatures,
		}).Define()
	}
})

type issuerBuilder struct {
	isClusterIssuer bool
	prototype       *unstructured.Unstructured

	IssuerRef cmmeta.ObjectReference
}

func newIssuerBuilder(issuerKind string, isClusterIssuer bool) *issuerBuilder {
	return &issuerBuilder{
		isClusterIssuer: isClusterIssuer,
		prototype: &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "sample-issuer.example.com/v1alpha1",
				"kind":       issuerKind,
				"spec": map[string]interface{}{
					"url": "http://sample-issuer.example.com/api/v1",
				},
			},
		},
	}
}

func (o *issuerBuilder) nameForTestObject(f *framework.Framework, suffix string) types.NamespacedName {
	namespace := f.Namespace.Name
	if o.isClusterIssuer {
		namespace = sampleExternalIssuerNamespace
	}

	return types.NamespacedName{
		Name:      fmt.Sprintf("%s-%s", f.Namespace.Name, suffix),
		Namespace: namespace,
	}
}

func (o *issuerBuilder) secretAndIssuerForTest(f *framework.Framework) (*corev1.Secret, *unstructured.Unstructured, error) {
	secretName := o.nameForTestObject(f, "credentials")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName.Name,
			Namespace: secretName.Namespace,
		},
		StringData: map[string]string{},
	}

	issuerName := o.nameForTestObject(f, "issuer")
	issuer := o.prototype.DeepCopy()
	issuer.SetName(issuerName.Name)
	issuer.SetNamespace(issuerName.Namespace)
	err := unstructured.SetNestedField(issuer.Object, secret.Name, "spec", "authSecretName")

	return secret, issuer, err
}

func (o *issuerBuilder) createIssuer(ctx context.Context, f *framework.Framework) {
	By("Creating an Issuer")

	secret, issuer, err := o.secretAndIssuerForTest(f)
	Expect(err).NotTo(HaveOccurred(), "failed to initialise test objects")

	err = f.CRClient.Create(ctx, secret)
	Expect(err).NotTo(HaveOccurred(), "failed to create secret")

	err = f.CRClient.Create(ctx, issuer)
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer")

	o.IssuerRef = cmmeta.ObjectReference{
		Group: issuer.GroupVersionKind().Group,
		Kind:  issuer.GroupVersionKind().Kind,
		Name:  issuer.GetName(),
	}
}

func (o *issuerBuilder) deleteIssuer(ctx context.Context, f *framework.Framework) {
	By("Deleting the issuer")

	secret, issuer, err := o.secretAndIssuerForTest(f)
	Expect(err).NotTo(HaveOccurred(), "failed to initialise test objects")

	err = f.CRClient.Delete(ctx, issuer)
	Expect(err).NotTo(HaveOccurred(), "failed to delete issuer")

	err = f.CRClient.Delete(ctx, secret)
	Expect(err).NotTo(HaveOccurred(), "failed to delete secret")
}
