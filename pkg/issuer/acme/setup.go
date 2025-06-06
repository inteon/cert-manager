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

package acme

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/pkg/acme"
	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/errors"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	acmeapi "github.com/cert-manager/cert-manager/third_party/forked/acme"
)

const (
	errorAccountRegistrationFailed = "ErrRegisterACMEAccount"
	errorAccountVerificationFailed = "ErrVerifyACMEAccount"
	errorAccountUpdateFailed       = "ErrUpdateACMEAccount"
	errorInvalidConfig             = "InvalidConfig"
	errorInvalidURL                = "InvalidURL"

	successAccountRegistered = "ACMEAccountRegistered"
	successAccountVerified   = "ACMEAccountVerified"

	messageAccountRegistrationFailed     = "Failed to register ACME account: "
	messageAccountVerificationFailed     = "Failed to verify ACME account: "
	messageAccountUpdateFailed           = "Failed to update ACME account:"
	messageAccountRegistered             = "The ACME account was registered with the ACME server"
	messageAccountVerified               = "The ACME account was verified with the ACME server"
	messageNoSecretKeyGenerationDisabled = "the ACME issuer config has 'disableAccountKeyGeneration' set to true, but the secret was not found: "
	messageInvalidPrivateKey             = "Account private key is invalid: "

	messageTemplateUpdateToV2              = "Your ACME server URL is set to a v1 endpoint (%s). You should update the spec.acme.server field to %q"
	messageTemplateNotRSA                  = "ACME private key in %q is not of type RSA"
	messageTemplateFailedToParseURL        = "Failed to parse existing ACME server URI %q: %v"
	messageTemplateFailedToParseAccountURL = "Failed to parse existing ACME account URI %q: %v"
	messageTemplateFailedToGetEABKey       = "failed to get External Account Binding key from secret: %v"
)

// Setup will verify an existing ACME registration, or create one if not
// already registered.
func (a *Acme) Setup(ctx context.Context, issuer v1.GenericIssuer) error {
	log := logf.FromContext(ctx)

	setIssuerReadyFailed := func(reason, msg string) {
		apiutil.SetIssuerCondition(issuer,
			issuer.GetGeneration(),
			v1.IssuerConditionReady,
			cmmeta.ConditionFalse,
			reason,
			msg)
	}

	// check if user has specified a v1 account URL, and set a status condition if so.
	if newURL, ok := acmev1ToV2Mappings[issuer.GetSpec().ACME.Server]; ok {
		err := fmt.Errorf(messageTemplateUpdateToV2, issuer.GetSpec().ACME.Server, newURL)
		setIssuerReadyFailed(errorInvalidConfig, err.Error())
		// Return nil, because we do not want to re-queue an Issuer with an invalid spec.
		return nil
	}

	if _, err := url.Parse(issuer.GetSpec().ACME.Server); err != nil {
		err := fmt.Errorf(messageTemplateFailedToParseURL, issuer.GetSpec().ACME.Server, err)
		a.recorder.Event(issuer, corev1.EventTypeWarning, errorInvalidURL, err.Error())
		setIssuerReadyFailed(errorInvalidURL, err.Error())
		// absorb errors as retrying will not help resolve this error
		return nil
	}

	// if the namespace field is not set, we are working on a ClusterIssuer resource
	// therefore we should check for the ACME private key in the 'cluster resource namespace'.
	ns := a.resourceNamespace(issuer)

	log = logf.WithRelatedResourceName(log, issuer.GetSpec().ACME.PrivateKey.Name, ns, "Secret")

	// attempt to obtain the existing private key from the apiserver.
	// if it does not exist then we generate one
	// if it contains invalid data, warn the user and return without error.
	// if any other error occurs, return it and retry.
	var rsaPk *rsa.PrivateKey
	{
		privateKeySelector := acme.PrivateKeySelector(issuer.GetSpec().ACME.PrivateKey)
		pk, err := a.keyFromSecret(ctx, ns, privateKeySelector.Name, privateKeySelector.Key)
		switch {
		case !issuer.GetSpec().ACME.DisableAccountKeyGeneration && apierrors.IsNotFound(err):
			log.V(logf.InfoLevel).Info("generating acme account private key")
			pk, err = a.createAccountPrivateKey(ctx, privateKeySelector, ns)
			if err != nil {
				err := fmt.Errorf("%s%s", messageAccountRegistrationFailed, err)
				setIssuerReadyFailed(errorAccountRegistrationFailed, err.Error())
				return err
			}

		case issuer.GetSpec().ACME.DisableAccountKeyGeneration && apierrors.IsNotFound(err):
			err := fmt.Errorf("%s%s%v", messageAccountVerificationFailed, messageNoSecretKeyGenerationDisabled, err)
			setIssuerReadyFailed(errorAccountVerificationFailed, err.Error())
			return err

		case errors.IsInvalidData(err):
			err := fmt.Errorf("%s%v", messageInvalidPrivateKey, err)
			setIssuerReadyFailed(errorAccountVerificationFailed, err.Error())
			// Return nil, because we do not want to re-queue an Issuer with an invalid spec.
			return nil

		case err != nil:
			err := fmt.Errorf("%s%s", messageAccountVerificationFailed, err)
			setIssuerReadyFailed(errorAccountVerificationFailed, err.Error())
			return err
		}

		castKey, ok := pk.(*rsa.PrivateKey)
		if !ok {
			err := fmt.Errorf(messageTemplateNotRSA, issuer.GetSpec().ACME.PrivateKey.Name)
			setIssuerReadyFailed(errorAccountVerificationFailed, err.Error())
			return nil
		}

		rsaPk = castKey
	}

	acmeClientOptions := accounts.RegistryItem{
		NewClientOptions: accounts.NewClientOptions{
			SkipTLSVerify: issuer.GetSpec().ACME.SkipTLSVerify,
			CABundle:      issuer.GetSpec().ACME.CABundle,
			Server:        issuer.GetSpec().ACME.Server,
			PrivateKey:    rsaPk,
		},

		Email: issuer.GetSpec().ACME.Email,
	}

	// ensure the cached client in the account registry is up to date
	a.accountRegistry.AddClient(string(issuer.GetUID()), acmeClientOptions)

	if issuerIsReady := apiutil.IssuerHasCondition(issuer, v1.IssuerCondition{
		Type:   v1.IssuerConditionReady,
		Status: cmmeta.ConditionTrue,
	}); issuerIsReady {
		// The issuer is in the Ready state, we will confirm that the ACME account
		// described in the Spec was registred by comparing its options with the spec
		// of the issuer.
		if acmeClientOptions.IsRegistered(issuer.GetStatus().ACME) {
			log.V(logf.InfoLevel).Info("skipping re-verifying ACME account as cached registration details look sufficient")
			// Issuer is already ready and ACME status
			// is up-to-date, don't update status.
			return nil
		}
	}

	// Reset status of issuer; so if we error below, the ACME status is emptied instead
	// of
	issuer.GetStatus().ACME = nil

	var eabAccount *acmeapi.ExternalAccountBinding
	if eabObj := issuer.GetSpec().ACME.ExternalAccountBinding; eabObj != nil {
		eabKey, err := a.getEABKey(ctx, ns, eabObj.Key)
		switch {
		// Do not re-try if we fail to get the MAC key as it does not exist at the reference.
		case apierrors.IsNotFound(err), errors.IsInvalidData(err):
			log.Error(err, "failed to verify ACME account")
			err := fmt.Errorf("%s%s", messageAccountRegistrationFailed, err)
			a.recorder.Event(issuer, corev1.EventTypeWarning, errorAccountRegistrationFailed, err.Error())
			setIssuerReadyFailed(errorAccountRegistrationFailed, err.Error())
			return nil

		case err != nil:
			err := fmt.Errorf("%s%s", messageAccountRegistrationFailed, err)
			a.recorder.Event(issuer, corev1.EventTypeWarning, errorAccountRegistrationFailed, err.Error())
			setIssuerReadyFailed(errorAccountRegistrationFailed, err.Error())
			return err
		}

		// set the external account binding
		eabAccount = &acmeapi.ExternalAccountBinding{
			KID: eabObj.KeyID,
			Key: eabKey,
		}
	}

	// register an ACME account or retrieve it if it already exists.
	acmeStatus, err := acmeClientOptions.Register(ctx, a.clientBuilder, eabAccount)
	if err != nil {
		err := fmt.Errorf("%s%s", messageAccountRegistrationFailed, err)
		setIssuerReadyFailed(messageAccountRegistrationFailed, err.Error())
		log.Error(err, "failed to register an ACME account")

		acmeErr, ok := err.(*acmeapi.Error)
		// If this is not an ACME error, we will simply return it and retry later
		if !ok {
			return err
		}

		// If the status code is 400 (BadRequest), we will *not* retry this registration
		// as it implies that something about the request (i.e. email address or private key)
		// is invalid.
		if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
			log.Error(acmeErr, "skipping retrying account registration as a "+
				"BadRequest response was returned from the ACME server")
			return nil
		}

		// Otherwise if we receive anything other than a 400, we will retry.
		return err
	}

	log.V(logf.InfoLevel).Info("verified existing registration with ACME server")
	apiutil.SetIssuerCondition(issuer,
		issuer.GetGeneration(),
		v1.IssuerConditionReady,
		cmmeta.ConditionTrue,
		successAccountRegistered,
		messageAccountRegistered,
	)
	issuer.GetStatus().ACME = acmeStatus

	return nil
}

func (a *Acme) getEABKey(ctx context.Context, ns string, eab cmmeta.SecretKeySelector) ([]byte, error) {
	sec, err := a.secretsClient.Secrets(ns).Get(ctx, eab.Name, metav1.GetOptions{})
	// Surface IsNotFound API error to not cause re-sync
	if apierrors.IsNotFound(err) {
		return nil, err
	}

	if err != nil {
		return nil, fmt.Errorf(messageTemplateFailedToGetEABKey, err)
	}

	encodedKeyData, ok := sec.Data[eab.Key]
	if !ok {
		return nil, errors.NewInvalidData("failed to find external account binding key data in Secret %q at index %q", eab.Name, eab.Key)
	}

	// decode the base64 encoded secret key data.
	// we include this step to make it easier for end-users to encode secret
	// keys in case the CA provides a key that is not in standard, padded
	// base64 encoding.
	keyData := make([]byte, base64.RawURLEncoding.DecodedLen(len(encodedKeyData)))
	if _, err := base64.RawURLEncoding.Decode(keyData, encodedKeyData); err != nil {
		return nil, errors.NewInvalidData("failed to decode external account binding key data: %v", err)
	}

	return keyData, nil
}

// createAccountPrivateKey will generate a new RSA private key, and create it
// as a secret resource in the apiserver.
func (a *Acme) createAccountPrivateKey(ctx context.Context, sel cmmeta.SecretKeySelector, ns string) (*rsa.PrivateKey, error) {
	sel = acme.PrivateKeySelector(sel)
	accountPrivKey, err := pki.GenerateRSAPrivateKey(pki.MinRSAKeySize)
	if err != nil {
		return nil, err
	}

	_, err = a.secretsClient.Secrets(ns).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sel.Name,
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "cert-manager",
			},
		},
		Data: map[string][]byte{
			sel.Key: pki.EncodePKCS1PrivateKey(accountPrivKey),
		},
	}, metav1.CreateOptions{})

	if err != nil {
		return nil, err
	}

	return accountPrivKey, err
}

var (
	acmev1Staging = "https://acme-staging.api.letsencrypt.org/directory"
	acmev1Prod    = "https://acme-v01.api.letsencrypt.org/directory"
	acmev2Staging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmev2Prod    = "https://acme-v02.api.letsencrypt.org/directory"
)

var acmev1ToV2Mappings = map[string]string{
	acmev1Prod:    acmev2Prod,
	acmev1Staging: acmev2Staging,
	// trailing slashes for v1 URLs
	fmt.Sprintf("%s/", acmev1Prod):    acmev2Prod,
	fmt.Sprintf("%s/", acmev1Staging): acmev2Staging,
}
