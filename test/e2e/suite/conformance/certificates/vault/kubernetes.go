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

package vault

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
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/vault"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
)

var _ = framework.ConformanceDescribe("CertificateSigningRequests", func() {
	frwork := framework.NewDefaultFramework("vault-certificates")

	var unsupportedFeatures = featureset.NewFeatureSet(
		featureset.KeyUsagesFeature,
		// Vault does not support signing using Ed25519
		featureset.Ed25519FeatureSet,
		featureset.SaveRootCAToSecret,
		featureset.IssueCAFeature,
		featureset.LiteralSubjectFeature,
	)

	{
		issuer := &vaultKubernetesProvisioner{
			testWithRootCA: true,
		}
		(&certificates.Suite{
			Name: "Vault Kubernetes Auth Issuer With Root CA",
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
		issuer := &vaultKubernetesProvisioner{
			testWithRootCA: false,
		}
		(&certificates.Suite{
			Name: "Vault Kubernetes Auth Issuer Without Root CA",
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
		issuer := &vaultKubernetesProvisioner{
			testWithRootCA: true,
		}
		(&certificates.Suite{
			Name: "Vault Kubernetes Auth ClusterIssuer With Root CA",
			CompleteHook: func(ctx context.Context, s *certificates.Suite) {
				s.KubeClientConfig = frwork.KubeClientConfig
				s.Namespace = frwork.Namespace.Name
				issuer.createClusterIssuer(ctx, frwork)
				s.IssuerRef = issuer.IssuerRef

				DeferCleanup(func(ctx context.Context) {
					issuer.deleteClusterIssuer(ctx, frwork)
				})
			},
			UnsupportedFeatures: unsupportedFeatures,
		}).Define()
	}

	{
		issuer := &vaultKubernetesProvisioner{
			testWithRootCA: false,
		}
		(&certificates.Suite{
			Name: "Vault Kubernetes Auth ClusterIssuer Without Root CA",
			CompleteHook: func(ctx context.Context, s *certificates.Suite) {
				s.KubeClientConfig = frwork.KubeClientConfig
				s.Namespace = frwork.Namespace.Name
				issuer.createClusterIssuer(ctx, frwork)
				s.IssuerRef = issuer.IssuerRef

				DeferCleanup(func(ctx context.Context) {
					issuer.deleteClusterIssuer(ctx, frwork)
				})
			},
			UnsupportedFeatures: unsupportedFeatures,
		}).Define()
	}
})

type vaultKubernetesProvisioner struct {
	setup          *vault.VaultInitializer
	IssuerRef      cmmeta.ObjectReference
	SignerName     string
	testWithRootCA bool
	// saTokenSecretName is the name of the Secret containing the service account token
	saTokenSecretName string
}

func (v *vaultKubernetesProvisioner) createIssuer(ctx context.Context, f *framework.Framework) {
	By("Creating a VaultKubernetes Issuer")

	v.initVault(f, f.Namespace.Name)

	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-issuer-",
		},
		Spec: v.createIssuerSpec(f),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create vault issuer")

	// wait for issuer to be ready
	By("Waiting for VaultKubernetes Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	v.IssuerRef = cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
	v.SignerName = fmt.Sprintf("issuers.cert-manager.io/%s.%s", f.Namespace.Name, issuer.Name)
}

func (v *vaultKubernetesProvisioner) deleteIssuer(ctx context.Context, f *framework.Framework) {
	Expect(v.setup.Clean()).NotTo(HaveOccurred(), "failed to deprovision vault initializer")

	err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(ctx, v.IssuerRef.Name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func (v *vaultKubernetesProvisioner) createClusterIssuer(ctx context.Context, f *framework.Framework) {
	By("Creating a VaultKubernetes ClusterIssuer")

	v.initVault(f, f.Config.Addons.CertManager.ClusterResourceNamespace)

	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(ctx, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "vault-cluster-issuer-",
		},
		Spec: v.createIssuerSpec(f),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create vault issuer")

	// wait for issuer to be ready
	By("Waiting for VaultKubernetes Cluster Issuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	v.IssuerRef = cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
	v.SignerName = fmt.Sprintf("clusterissuers.cert-manager.io/%s", issuer.Name)
}

func (v *vaultKubernetesProvisioner) deleteClusterIssuer(ctx context.Context, f *framework.Framework) {
	Expect(v.setup.Clean()).NotTo(HaveOccurred(), "failed to deprovision vault initializer")

	v.setup.CleanKubernetesRole(f.KubeClientSet, f.Config.Addons.CertManager.ClusterResourceNamespace, v.setup.Role())

	err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(ctx, v.IssuerRef.Name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func (v *vaultKubernetesProvisioner) initVault(f *framework.Framework, boundNS string) {
	By("Configuring the VaultKubernetes server")
	v.setup = vault.NewVaultInitializerKubernetes(
		addon.Base.Details().KubeClient,
		*addon.Vault.Details(),
		v.testWithRootCA,
		"https://kubernetes.default.svc.cluster.local",
	)
	Expect(v.setup.Init()).NotTo(HaveOccurred(), "failed to init vault")
	Expect(v.setup.Setup()).NotTo(HaveOccurred(), "failed to setup vault")

	By("Creating a ServiceAccount for Vault authentication")

	// boundNS is name of the service account for which a Secret containing the service account token will be created
	boundSA := "vault-issuer-" + util.RandStringRunes(5)
	err := v.setup.CreateKubernetesRole(f.KubeClientSet, boundNS, boundSA)
	Expect(err).NotTo(HaveOccurred())

	v.saTokenSecretName = "vault-sa-secret-" + util.RandStringRunes(5)
	_, err = f.KubeClientSet.CoreV1().Secrets(boundNS).Create(context.TODO(), vault.NewVaultKubernetesSecret(v.saTokenSecretName, boundSA), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func (v *vaultKubernetesProvisioner) createIssuerSpec(f *framework.Framework) cmapi.IssuerSpec {
	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			Vault: &cmapi.VaultIssuer{
				Server:   addon.Vault.Details().URL,
				Path:     v.setup.IntermediateSignPath(),
				CABundle: addon.Vault.Details().VaultCA,
				Auth: cmapi.VaultAuth{
					Kubernetes: &cmapi.VaultKubernetesAuth{
						Path: v.setup.KubernetesAuthPath(),
						Role: v.setup.Role(),
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: v.saTokenSecretName,
							},
						},
					},
				},
			},
		},
	}
}
