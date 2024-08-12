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

package policies

const (
	// DoesNotExist is a policy violation reason for a scenario where
	// Certificate's spec.secretName secret does not exist.
	DoesNotExist string = "DoesNotExist"
	// MissingData is a policy violation reason for a scenario where
	// Certificate's spec.secretName secret has missing data.
	MissingData string = "MissingData"
	// InvalidKeyPair is a policy violation reason for a scenario where public
	// key of certificate does not match private key.
	InvalidKeyPair string = "InvalidKeyPair"
	// InvalidManagedFields is a policy violation reason for a scenario where
	// managed fields on the Secret are invalid.
	InvalidManagedFields string = "InvalidManagedFields"
	// InvalidPrivateKey is a policy violation reason for a scenario where the
	// private key in the Input Secret could not be parsed or decoded.
	InvalidPrivateKey string = "InvalidPrivateKey"
	// InvalidCertificate is a policy violation whereby the signed certificate in
	// the Input Secret could not be parsed or decoded.
	InvalidCertificate string = "InvalidCertificate"
	// InvalidCertificateRequest is a policy violation whereby the CSR in
	// the Input CertificateRequest could not be parsed or decoded.
	InvalidCertificateRequest string = "InvalidCertificateRequest"
)

const (
	// IncorrectIssuer is a policy violation reason for a scenario where
	// Certificate has been issued by incorrect Issuer.
	IncorrectIssuer string = "IncorrectIssuer"
	// IncorrectCertificate is a policy violation reason for a scenario where
	// the Secret referred to by this Certificate's spec.secretName,
	// already has a `cert-manager.io/certificate-name` annotation
	// with the name of another Certificate.
	IncorrectCertificate string = "IncorrectCertificate"

	// SecretMismatch is a policy violation reason for a scenario where Secret's
	// private key does not match spec.
	SecretMismatch string = "SecretMismatch"
	// RequestChanged is a policy violation reason for a scenario where
	// CertificateRequest not valid for Certificate's spec.
	RequestChanged string = "RequestChanged"

	// Renewing is a policy violation reason for a scenario where
	// Certificate's renewal time is now or in past.
	Renewing string = "Renewing"
	// Expired is a policy violation reason for a scenario where Certificate has
	// expired.
	Expired string = "Expired"
)

const (
	// SecretMetadataMismatch is a policy violation whereby the Secret has
	// extra, missing, or wrong Annotations or Labels. The expected set of labels
	// and annotations are based on the Certificate's SecretTemplate and the
	// labels and annotations managed by cert-manager.
	SecretMetadataMismatch string = "SecretMetadataMismatch"
	// AdditionalOutputFormatsMismatch is a policy violation whereby the
	// Certificate's AdditionalOutputFormats is not reflected on the target
	// Secret, either by having extra, missing, or wrong values.
	AdditionalOutputFormatsMismatch string = "AdditionalOutputFormatsMismatch"
	// SecretOwnerRefMismatch is a policy violation whereby the Secret either has
	// a missing owner reference to the Certificate, or has an owner reference it
	// shouldn't have.
	SecretOwnerRefMismatch string = "SecretOwnerRefMismatch"
	// SecretKeystoreMismatch is a policy violation whereby the Secret does not have
	// the requested keystore formats.
	SecretKeystoreMismatch string = "SecretKeystoreMismatch"
)
