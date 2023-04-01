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

package informers

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	kubeinformers "k8s.io/client-go/informers"
	certificatesv1 "k8s.io/client-go/informers/certificates/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	networkingv1informers "k8s.io/client-go/informers/networking/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/metadata/metadatalister"
	"k8s.io/client-go/tools/cache"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// This file contains all the functionality for implementing core informers with a filter for Secrets
// https://github.com/cert-manager/cert-manager/blob/master/design/20221205-memory-management.md
var (
	isCertManageSecretLabelSelector     labels.Selector
	isNotCertManagerSecretLabelSelector labels.Selector
)

func init() {
	r, err := labels.NewRequirement(cmapi.PartOfCertManagerControllerLabelKey, selection.Equals, []string{"true"})
	if err != nil {
		panic(fmt.Errorf("internal error: failed to build label selector to filter cert-manager secrets: %w", err))
	}
	isCertManageSecretLabelSelector = labels.NewSelector().Add(*r)

	r, err = labels.NewRequirement(cmapi.PartOfCertManagerControllerLabelKey, selection.DoesNotExist, nil)
	if err != nil {
		panic(fmt.Errorf("internal error: failed to build label selector to filter non-cert-manager secrets: %w", err))
	}
	isNotCertManagerSecretLabelSelector = labels.NewSelector().Add(*r)
}

type filteredSecretsFactory struct {
	typedInformerFactory    kubeinformers.SharedInformerFactory
	metadataInformerFactory metadatainformer.SharedInformerFactory
	client                  kubernetes.Interface
	namespace               string
}

func NewFilteredSecretsKubeInformerFactory(typedClient kubernetes.Interface, metadataClient metadata.Interface, resync time.Duration, namespace string) KubeInformerFactory {
	return &filteredSecretsFactory{
		typedInformerFactory: kubeinformers.NewSharedInformerFactoryWithOptions(typedClient, resync, kubeinformers.WithNamespace(namespace)),
		metadataInformerFactory: metadatainformer.NewFilteredSharedInformerFactory(metadataClient, resync, namespace, func(listOptions *metav1.ListOptions) {
			listOptions.LabelSelector = isNotCertManagerSecretLabelSelector.String()

		}),
		// namespace is set to a non-empty value if cert-manager
		// controller is scoped to a single namespace via --namespace
		// flag
		namespace: namespace,
		client:    typedClient,
	}
}

func (bf *filteredSecretsFactory) Start(stopCh <-chan struct{}) {
	bf.typedInformerFactory.Start(stopCh)
	bf.metadataInformerFactory.Start(stopCh)
}

func (bf *filteredSecretsFactory) WaitForCacheSync(stopCh <-chan struct{}) map[string]bool {
	caches := make(map[string]bool)
	typedCaches := bf.typedInformerFactory.WaitForCacheSync(stopCh)
	partialMetaCaches := bf.metadataInformerFactory.WaitForCacheSync(stopCh)
	// We have to cast the keys into string type. It is not possible to
	// create a generic type here as neither of the types returned by
	// WaitForCacheSync are valid map key arguments in generics- they aren't
	// comparable types.
	for key, val := range typedCaches {
		caches[key.String()] = val
	}
	for key, val := range partialMetaCaches {
		caches[key.String()] = val
	}
	return caches
}

func (bf *filteredSecretsFactory) Pods() corev1informers.PodInformer {
	return bf.typedInformerFactory.Core().V1().Pods()
}

func (bf *filteredSecretsFactory) Services() corev1informers.ServiceInformer {
	return bf.typedInformerFactory.Core().V1().Services()
}

func (bf *filteredSecretsFactory) Ingresses() networkingv1informers.IngressInformer {
	return bf.typedInformerFactory.Networking().V1().Ingresses()
}

func (bf *filteredSecretsFactory) CertificateSigningRequests() certificatesv1.CertificateSigningRequestInformer {
	return bf.typedInformerFactory.Certificates().V1().CertificateSigningRequests()
}

func (bf *filteredSecretsFactory) Secrets() SecretInformer {
	return &filteredSecretInformer{
		typedInformerFactory:    bf.typedInformerFactory,
		metadataInformerFactory: bf.metadataInformerFactory,
		namespace:               bf.namespace,
		typedClient:             bf.client.CoreV1(),
	}
}

// filteredSecretInformer is an implementation of SecretInformer that uses two
// caches (typed and metadata) to list and watch Secrets
type filteredSecretInformer struct {
	typedInformerFactory    kubeinformers.SharedInformerFactory
	metadataInformerFactory metadatainformer.SharedInformerFactory
	typedClient             typedcorev1.SecretsGetter

	namespace string
}

func (f *filteredSecretInformer) newTyped(client kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return corev1informers.NewFilteredSecretInformer(
		client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, func(listOptions *metav1.ListOptions) {
			listOptions.LabelSelector = isCertManageSecretLabelSelector.String()
		},
	)
}

func (f *filteredSecretInformer) Informer() Informer {
	typedInformer := f.typedInformerFactory.InformerFor(&corev1.Secret{}, f.newTyped)
	// TODO: set any possible transforms
	metadataInformer := f.metadataInformerFactory.ForResource(secretsGVR).Informer()
	// TODO: set transform on metadataInformer to remove last applied annotation etc
	return &informer{
		typedInformer:    typedInformer,
		metadataInformer: metadataInformer,
	}
}

func (f *filteredSecretInformer) Lister() SecretLister {
	typedLister := corev1listers.NewSecretLister(f.typedInformerFactory.InformerFor(&corev1.Secret{}, f.newTyped).GetIndexer())
	metadataLister := metadatalister.New(f.metadataInformerFactory.ForResource(secretsGVR).Informer().GetIndexer(), secretsGVR)
	return &secretLister{
		typedClient:           f.typedClient,
		namespace:             f.namespace,
		typedLister:           typedLister,
		partialMetadataLister: metadataLister,
	}
}

// informer is an implementation of Informer interface
type informer struct {
	typedInformer    cache.SharedIndexInformer
	metadataInformer cache.SharedIndexInformer
}

func (i *informer) HasSynced() bool {
	return i.typedInformer.HasSynced() && i.metadataInformer.HasSynced()
}

func (i *informer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	// TODO: fix registration return value
	_, err := i.metadataInformer.AddEventHandler(handler)
	if err != nil {
		return nil, err
	}
	_, err = i.typedInformer.AddEventHandler(handler)
	return nil, err
}

// secretLister is an implementation of SecretLister with a namespaced lister
// that knows how to do conditional GET/LIST of Secrets using a combination of
// typed and metadata cache and kube apiserver
type secretLister struct {
	namespace             string
	partialMetadataLister metadatalister.Lister
	typedLister           corev1listers.SecretLister
	typedClient           typedcorev1.SecretsGetter
}

func (sl *secretLister) Secrets(namespace string) SecretNamespaceLister {
	return &secretNamespaceLister{
		namespace:    namespace,
		secretLister: *sl,
	}
}

var _ SecretNamespaceLister = &secretNamespaceLister{}

// secretNamespaceLister is an implementation of
// corelisters.SecretNamespaceLister
// https://github.com/kubernetes/client-go/blob/0382bf0f53b2294d4ac448203718f0ba774a477d/listers/core/v1/secret.go#L62-L72.
// It knows how to get and list Secrets using typed and partial metadata caches
// and kube apiserver. It looks for Secrets in both caches, if the Secret is
// found in metadata cache, it will retrieve it from kube apiserver.
type secretNamespaceLister struct {
	namespace string
	secretLister
}

func (snl *secretNamespaceLister) Get(ctx context.Context, name string) (*corev1.Secret, error) {
	log := logf.FromContext(ctx)
	log = log.WithValues("secret", name, "namespace", snl.namespace)
	key := types.NamespacedName{Namespace: snl.namespace, Name: name}

	var secretFoundInTypedCache, secretFoundInMetadataCache bool
	secret, typedCacheErr := snl.typedLister.Secrets(key.Namespace).Get(key.Name)
	if typedCacheErr == nil {
		secretFoundInTypedCache = true
	} else if !apierrors.IsNotFound(typedCacheErr) {
		log.Error(typedCacheErr, "error getting Secrets from typed cache", "secret", key)
		return nil, typedCacheErr
	}

	_, partialMetadataGetErr := snl.partialMetadataLister.Namespace(key.Namespace).Get(key.Name)
	if partialMetadataGetErr == nil {
		secretFoundInMetadataCache = true
	} else if !apierrors.IsNotFound(partialMetadataGetErr) {
		log.Error(typedCacheErr, "error getting Secrets from partial object metadata cache", "secret", key)
		return nil, partialMetadataGetErr
	}

	if secretFoundInMetadataCache {
		// if secret is found in both caches log an error and return the version from kube apiserver
		if secretFoundInTypedCache {
			log.Info(fmt.Sprintf("warning: possible internal error: stale cache: secret found both in typed cache and in partial cache: %s", pleaseOpenIssue), "secret", key)
		}

		secret, err := snl.typedClient.Secrets(key.Namespace).Get(ctx, key.Name, metav1.GetOptions{})
		if err != nil {
			log.Error(err, "error retrieving secret from kube apiserver", "secret", key)
			return nil, err
		}
		return secret, nil
	}

	if secretFoundInTypedCache {
		return secret, nil
	}

	// If we get here it is because secret was found neither in typed cache
	// nor partial metadata cache
	return nil, apierrors.NewNotFound(schema.GroupResource{Group: corev1.GroupName, Resource: corev1.ResourceSecrets.String()}, name)
}

func (snl *secretNamespaceLister) List(ctx context.Context, selector labels.Selector) ([]*corev1.Secret, error) {
	log := logf.FromContext(ctx)
	log = log.WithValues("secrets namespace", snl.namespace, "secrets selector", selector.String())

	matchingSecretsMap := make(map[types.NamespacedName]*corev1.Secret)

	typedSecrets, err := snl.typedLister.List(selector)
	if err != nil {
		log.Error(err, "error listing Secrets from typed cache")
		return nil, err
	}
	for _, secret := range typedSecrets {
		key := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
		matchingSecretsMap[key] = secret
	}

	metadataSecrets, err := snl.partialMetadataLister.List(selector)
	if err != nil {
		log.Error(err, "error listing Secrets from metadata only cache")
		return nil, err
	}

	// In practice this section will likely never be used. The only place
	// where we LIST Secrets is in keymanager controller where we list
	// temporary Certificate Secrets which are all labelled.
	// It is unlikely that we will every list unlabelled Secrets.
	for _, secretMeta := range metadataSecrets {
		key := types.NamespacedName{Namespace: secretMeta.Namespace, Name: secretMeta.Name}
		if _, ok := matchingSecretsMap[key]; ok {
			log.Info(fmt.Sprintf("warning: possible internal error: stale cache: secret found both in typed cache and in partial cache: %s", pleaseOpenIssue), "secret", key)
			// in case of duplicates, return the version from kube apiserver
		}

		secret, err := snl.typedClient.Secrets(key.Namespace).Get(ctx, key.Name, metav1.GetOptions{})
		if err != nil {
			log.Error(err, "error retrieving secret from kube apiserver", "secret", key)
			return nil, err
		}
		matchingSecretsMap[key] = secret
	}

	matchingSecrets := make([]*corev1.Secret, 0, len(matchingSecretsMap))
	for _, val := range matchingSecretsMap {
		matchingSecrets = append(matchingSecrets, val)
	}

	return matchingSecrets, nil
}
