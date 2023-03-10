/*
Copyright The cert-manager Authors.

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

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// VaultKubernetesAuthApplyConfiguration represents an declarative configuration of the VaultKubernetesAuth type for use
// with apply.
type VaultKubernetesAuthApplyConfiguration struct {
	Path              *string                              `json:"mountPath,omitempty"`
	SecretRef         *v1.SecretKeySelector                `json:"secretRef,omitempty"`
	ServiceAccountRef *ServiceAccountRefApplyConfiguration `json:"serviceAccountRef,omitempty"`
	Role              *string                              `json:"role,omitempty"`
}

// VaultKubernetesAuthApplyConfiguration constructs an declarative configuration of the VaultKubernetesAuth type for use with
// apply.
func VaultKubernetesAuth() *VaultKubernetesAuthApplyConfiguration {
	return &VaultKubernetesAuthApplyConfiguration{}
}

// WithPath sets the Path field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Path field is set to the value of the last call.
func (b *VaultKubernetesAuthApplyConfiguration) WithPath(value string) *VaultKubernetesAuthApplyConfiguration {
	b.Path = &value
	return b
}

// WithSecretRef sets the SecretRef field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SecretRef field is set to the value of the last call.
func (b *VaultKubernetesAuthApplyConfiguration) WithSecretRef(value v1.SecretKeySelector) *VaultKubernetesAuthApplyConfiguration {
	b.SecretRef = &value
	return b
}

// WithServiceAccountRef sets the ServiceAccountRef field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ServiceAccountRef field is set to the value of the last call.
func (b *VaultKubernetesAuthApplyConfiguration) WithServiceAccountRef(value *ServiceAccountRefApplyConfiguration) *VaultKubernetesAuthApplyConfiguration {
	b.ServiceAccountRef = value
	return b
}

// WithRole sets the Role field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Role field is set to the value of the last call.
func (b *VaultKubernetesAuthApplyConfiguration) WithRole(value string) *VaultKubernetesAuthApplyConfiguration {
	b.Role = &value
	return b
}
