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

package venafi

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"issuerconformance/certificates"
	"issuerconformance/framework/helper/featureset"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/venafi"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/util/errors"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmutil "github.com/cert-manager/cert-manager/pkg/util"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	frwork := framework.NewDefaultFramework("venafi-certificates")
	// unsupportedFeatures is a list of features that are not supported by the
	// Venafi TPP issuer.
	var unsupportedFeatures = featureset.NewFeatureSet(
		// Venafi TPP doesn't allow setting a duration
		featureset.DurationFeature,
		// Due to the current configuration of the test environment, it does not
		// support signing certificates that pair with an elliptic curve or
		// Ed255119 private keys
		featureset.ECDSAFeature,
		featureset.Ed25519FeatureSet,
		// Our Venafi TPP doesn't allow setting non DNS SANs
		// TODO: investigate options to enable these
		featureset.EmailSANsFeature,
		featureset.URISANsFeature,
		featureset.IPAddressFeature,
		// Venafi doesn't allow certs with empty CN & DN
		featureset.OnlySAN,
	)

	{
		issuer := new(tppProvisioner)
		(&certificates.Suite{
			Name: "Venafi TPP Issuer",
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
			DomainSuffix:        fmt.Sprintf("%s-venafi-e2e", cmutil.RandStringRunes(5)),
		}).Define()
	}

	{
		issuer := new(tppProvisioner)
		(&certificates.Suite{
			Name: "Venafi TPP ClusterIssuer",
			CompleteHook: func(ctx context.Context, s *certificates.Suite) {
				s.KubeClientConfig = frwork.KubeClientConfig
				s.Namespace = frwork.Namespace.Name
				issuer.createClusterIssuer(ctx, frwork)
				s.IssuerRef = issuer.IssuerRef

				DeferCleanup(func(ctx context.Context) {
					issuer.deleteIssuer(ctx, frwork)
				})
			},
			UnsupportedFeatures: unsupportedFeatures,
			DomainSuffix:        fmt.Sprintf("%s-venafi-e2e", cmutil.RandStringRunes(5)),
		}).Define()
	}
})

type tppProvisioner struct {
	*venafi.VenafiTPP
	IssuerRef  cmmeta.ObjectReference
	SignerName string
}

func (v *tppProvisioner) createIssuer(ctx context.Context, f *framework.Framework) {
	By("Creating a Venafi Issuer")

	v.VenafiTPP = &venafi.VenafiTPP{
		Namespace: f.Namespace.Name,
	}

	_, err := v.Setup(f.Config)
	if errors.IsSkip(err) {
		framework.Skipf("Skipping test as addon could not be setup: %v", err)
	}
	Expect(err).NotTo(HaveOccurred(), "failed to setup tpp venafi")

	Expect(v.Provision()).NotTo(HaveOccurred(), "failed to provision tpp venafi")

	issuer := v.Details().BuildIssuer()
	issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer for venafi")

	// wait for issuer to be ready
	By("Waiting for Venafi Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	v.IssuerRef = cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
	v.SignerName = fmt.Sprintf("issuers.cert-manager.io/%s.%s", f.Namespace.Name, issuer.Name)
}

func (v *tppProvisioner) deleteIssuer(ctx context.Context, f *framework.Framework) {
	Expect(v.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision tpp venafi")

	err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(ctx, v.IssuerRef.Name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to delete tpp issuer")
}

func (v *tppProvisioner) createClusterIssuer(ctx context.Context, f *framework.Framework) {
	By("Creating a Venafi ClusterIssuer")

	v.VenafiTPP = &venafi.VenafiTPP{
		Namespace: f.Config.Addons.CertManager.ClusterResourceNamespace,
	}

	_, err := v.Setup(f.Config)
	if errors.IsSkip(err) {
		framework.Skipf("Skipping test as addon could not be setup: %v", err)
	}
	Expect(err).NotTo(HaveOccurred(), "failed to setup tpp venafi")

	Expect(v.Provision()).NotTo(HaveOccurred(), "failed to provision tpp venafi")

	issuer := v.Details().BuildClusterIssuer()
	issuer, err = f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer for venafi")

	// wait for issuer to be ready
	By("Waiting for Venafi Cluster Issuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	v.IssuerRef = cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
	v.SignerName = fmt.Sprintf("clusterissuers.cert-manager.io/%s", issuer.Name)
}

func (v *tppProvisioner) deleteClusterIssuer(ctx context.Context, f *framework.Framework) {
	Expect(v.Deprovision()).NotTo(HaveOccurred(), "failed to deprovision tpp venafi")

	err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(ctx, v.IssuerRef.Name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to delete ca issuer")
}
