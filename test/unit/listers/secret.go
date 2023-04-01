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

package listers

import (
	"context"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

var _ internalinformers.SecretLister = &FakeSecretLister{}
var _ internalinformers.SecretNamespaceLister = &FakeSecretNamespaceLister{}

type FakeSecretListerModifier func(*FakeSecretLister)
type FakeSecretNamespaceListerModifier func(*FakeSecretNamespaceLister)

type FakeSecretLister struct {
	SecretsFn func(namespace string) internalinformers.SecretNamespaceLister
}

type FakeSecretNamespaceLister struct {
	ListFn func(ctx context.Context, selector labels.Selector) (ret []*corev1.Secret, err error)
	GetFn  func(ctx context.Context, name string) (ret *corev1.Secret, err error)
}

func NewFakeSecretLister(mods ...FakeSecretListerModifier) *FakeSecretLister {
	return FakeSecretListerFrom(&FakeSecretLister{
		SecretsFn: func(namespace string) internalinformers.SecretNamespaceLister {
			return nil
		},
	}, mods...)
}

func NewFakeSecretNamespaceLister(mods ...FakeSecretNamespaceListerModifier) *FakeSecretNamespaceLister {
	return FakeSecretNamespaceListerFrom(&FakeSecretNamespaceLister{
		ListFn: func(ctx context.Context, selector labels.Selector) (ret []*corev1.Secret, err error) {
			return nil, nil
		},
		GetFn: func(ctx context.Context, name string) (ret *corev1.Secret, err error) {
			return nil, nil
		},
	}, mods...)
}

func (f *FakeSecretLister) Secrets(namespace string) internalinformers.SecretNamespaceLister {
	return f.SecretsFn(namespace)
}

func (f *FakeSecretNamespaceLister) List(ctx context.Context, selector labels.Selector) (ret []*corev1.Secret, err error) {
	return f.ListFn(ctx, selector)
}

func (f *FakeSecretNamespaceLister) Get(ctx context.Context, name string) (*corev1.Secret, error) {
	return f.GetFn(ctx, name)
}

func FakeSecretNamespaceListerFrom(f *FakeSecretNamespaceLister, mods ...FakeSecretNamespaceListerModifier) *FakeSecretNamespaceLister {
	for _, mod := range mods {
		mod(f)
	}
	return f
}

func (f *FakeSecretNamespaceLister) SetFakeSecretNamespaceListerGet(ret *corev1.Secret, err error) *FakeSecretNamespaceLister {
	f.GetFn = func(context.Context, string) (*corev1.Secret, error) {
		return ret, err
	}

	return f
}

func FakeSecretListerFrom(s *FakeSecretLister, mods ...FakeSecretListerModifier) *FakeSecretLister {
	for _, mod := range mods {
		mod(s)
	}
	return s
}

func SetFakeSecretListerSecret(s func(namespace string) internalinformers.SecretNamespaceLister) FakeSecretListerModifier {
	return func(f *FakeSecretLister) {
		f.SecretsFn = s
	}
}

func SetFakeSecretNamespaceListerGet(sec *corev1.Secret, err error) FakeSecretListerModifier {
	return func(f *FakeSecretLister) {
		f.SecretsFn = func(namespace string) internalinformers.SecretNamespaceLister {
			return &FakeSecretNamespaceLister{
				GetFn: func(ctx context.Context, name string) (*corev1.Secret, error) {
					return sec, err
				},
			}
		}
	}
}
