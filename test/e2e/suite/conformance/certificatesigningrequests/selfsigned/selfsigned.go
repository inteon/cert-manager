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

package selfsigned

import (
	"context"
	"crypto"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"issuerconformance/certificatesigningrequests"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

var _ = framework.ConformanceDescribe("CertificateSigningRequests", func() {
	frwork := framework.NewDefaultFramework("selfsigned-certificates")

	{
		issuer := new(selfsigned)
		(&certificatesigningrequests.Suite{
			Name: "SelfSigned Issuer",
			CompleteHook: func(ctx context.Context, s *certificatesigningrequests.Suite) {
				s.KubeClientConfig = frwork.KubeClientConfig
				issuer.createIssuer(ctx, frwork)
				s.SignerName = issuer.SignerName

				DeferCleanup(func(ctx context.Context) {
					issuer.deleteIssuer(ctx, frwork)
				})
			},
		}).Define()
	}

	{
		issuer := new(selfsigned)
		(&certificatesigningrequests.Suite{
			Name: "SelfSigned ClusterIssuer",
			CompleteHook: func(ctx context.Context, s *certificatesigningrequests.Suite) {
				s.KubeClientConfig = frwork.KubeClientConfig
				issuer.createClusterIssuer(ctx, frwork)
				s.SignerName = issuer.SignerName

				DeferCleanup(func(ctx context.Context) {
					issuer.deleteClusterIssuer(ctx, frwork)
				})
			},
		}).Define()
	}
})

type selfsigned struct {
	IssuerRef  cmmeta.ObjectReference
	SignerName string
}

func provision(f *framework.Framework, csr *certificatesv1.CertificateSigningRequest, key crypto.Signer) {
	By("Creating SelfSigned requester key Secret")
	ref, _ := util.SignerIssuerRefFromSignerName(csr.Spec.SignerName)
	ns := "cert-manager"
	if kind, _ := util.IssuerKindFromType(ref.Type); kind == cmapi.IssuerKind {
		ns = ref.Namespace
	}

	keyPEM, err := pki.EncodePKCS8PrivateKey(key)
	Expect(err).NotTo(HaveOccurred(), "failed to encode requester's private key")

	secret, err := f.KubeClientSet.CoreV1().Secrets(ns).Create(context.TODO(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "selfsigned-requester-key-",
			Namespace:    ns,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create requester's private key Secret")

	if csr.Annotations == nil {
		csr.Annotations = make(map[string]string)
	}
	csr.Annotations[experimentalapi.CertificateSigningRequestPrivateKeyAnnotationKey] = secret.Name
}
func deProvision(f *framework.Framework, csr *certificatesv1.CertificateSigningRequest) {
	By("Deleting SelfSigned requester key Secret")
	ref, _ := util.SignerIssuerRefFromSignerName(csr.Spec.SignerName)
	ns := f.Config.Addons.CertManager.ClusterResourceNamespace
	if kind, _ := util.IssuerKindFromType(ref.Type); kind == cmapi.IssuerKind {
		ns = ref.Namespace
	}

	err := f.KubeClientSet.CoreV1().Secrets(ns).Delete(context.TODO(), csr.Annotations[experimentalapi.CertificateSigningRequestPrivateKeyAnnotationKey], metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create requester's private key Secret")
}

func (c *selfsigned) createIssuer(ctx context.Context, f *framework.Framework) {
	By("Creating a SelfSigned Issuer")

	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "selfsigned-issuer-",
		},
		Spec: createSelfSignedIssuerSpec(),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create self signed issuer")

	// wait for issuer to be ready
	By("Waiting for Self Signed Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	c.IssuerRef = cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
	c.SignerName = fmt.Sprintf("issuers.cert-manager.io/%s.%s", f.Namespace.Name, issuer.Name)
}

func (c *selfsigned) deleteIssuer(ctx context.Context, f *framework.Framework) {
	By("Deleting SelfSigned Issuer")

	err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(ctx, c.IssuerRef.Name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to delete ca issuer")
}

func (c *selfsigned) createClusterIssuer(ctx context.Context, f *framework.Framework) {
	By("Creating a SelfSigned ClusterIssuer")

	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(ctx, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "selfsigned-cluster-issuer-",
		},
		Spec: createSelfSignedIssuerSpec(),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create self signed issuer")

	// wait for issuer to be ready
	By("Waiting for Self Signed Cluster Issuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	c.IssuerRef = cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
	c.SignerName = fmt.Sprintf("clusterissuers.cert-manager.io/%s", issuer.Name)
}

func (c *selfsigned) deleteClusterIssuer(ctx context.Context, f *framework.Framework) {
	err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(ctx, c.IssuerRef.Name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func createSelfSignedIssuerSpec() cmapi.IssuerSpec {
	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			SelfSigned: &cmapi.SelfSignedIssuer{},
		},
	}
}
