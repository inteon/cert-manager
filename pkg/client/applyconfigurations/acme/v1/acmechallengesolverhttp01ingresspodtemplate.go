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

// ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration represents an declarative configuration of the ACMEChallengeSolverHTTP01IngressPodTemplate type for use
// with apply.
type ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration struct {
	*ACMEChallengeSolverHTTP01IngressPodObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Spec                                                             *ACMEChallengeSolverHTTP01IngressPodSpecApplyConfiguration `json:"spec,omitempty"`
}

// ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration constructs an declarative configuration of the ACMEChallengeSolverHTTP01IngressPodTemplate type for use with
// apply.
func ACMEChallengeSolverHTTP01IngressPodTemplate() *ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration {
	return &ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration{}
}

// WithAnnotations puts the entries into the Annotations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Annotations field,
// overwriting an existing map entries in Annotations field with the same key.
func (b *ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration) WithAnnotations(entries map[string]string) *ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration {
	b.ensureACMEChallengeSolverHTTP01IngressPodObjectMetaApplyConfigurationExists()
	if b.Annotations == nil && len(entries) > 0 {
		b.Annotations = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Annotations[k] = v
	}
	return b
}

// WithLabels puts the entries into the Labels field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Labels field,
// overwriting an existing map entries in Labels field with the same key.
func (b *ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration) WithLabels(entries map[string]string) *ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration {
	b.ensureACMEChallengeSolverHTTP01IngressPodObjectMetaApplyConfigurationExists()
	if b.Labels == nil && len(entries) > 0 {
		b.Labels = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Labels[k] = v
	}
	return b
}

func (b *ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration) ensureACMEChallengeSolverHTTP01IngressPodObjectMetaApplyConfigurationExists() {
	if b.ACMEChallengeSolverHTTP01IngressPodObjectMetaApplyConfiguration == nil {
		b.ACMEChallengeSolverHTTP01IngressPodObjectMetaApplyConfiguration = &ACMEChallengeSolverHTTP01IngressPodObjectMetaApplyConfiguration{}
	}
}

// WithSpec sets the Spec field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Spec field is set to the value of the last call.
func (b *ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration) WithSpec(value *ACMEChallengeSolverHTTP01IngressPodSpecApplyConfiguration) *ACMEChallengeSolverHTTP01IngressPodTemplateApplyConfiguration {
	b.Spec = value
	return b
}
