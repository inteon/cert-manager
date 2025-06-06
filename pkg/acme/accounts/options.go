/*
Copyright 2024 The cert-manager Authors.

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

package accounts

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strings"

	acmeapi "github.com/cert-manager/cert-manager/third_party/forked/acme"

	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

type RegistryItem struct {
	NewClientOptions
	Email string
}

// we assume that all imporant options are in NewClientOptions,
// the NewClientFunc should not generate radically different clients
func (a RegistryItem) getClient(newFn NewClientFunc) acmecl.Interface {
	return newFn(a.NewClientOptions)
}

func (a RegistryItem) privateKeyHash() string {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(a.PrivateKey)
	checksum := sha256.Sum256(privateKeyBytes)
	checksumString := base64.StdEncoding.EncodeToString(checksum[:])
	return checksumString
}

func (co RegistryItem) IsRegistered(
	status *cmacme.ACMEIssuerStatus,
) bool {
	if status == nil ||
		status.URI == "" ||
		status.LastPrivateKeyHash == "" {
		// NOTE: we allow spec.Email and status.LastRegisteredEmail to be empty
		return false // The status is missing fields.
	}

	parsedServerURL, parseServerURLErr := url.Parse(co.Server)
	parsedAccountURL, parseAccountURLErr := url.Parse(status.URI)
	if parseServerURLErr != nil || parseAccountURLErr != nil {
		return false
	}

	// If the Host components of the server URL and the account URL match,
	// the cached email matches the registered email,
	// and the private key matches then
	// we skip re-checking the account status to save excess calls to the
	// ACME api.
	return status.LastRegisteredEmail == co.Email &&
		parsedAccountURL.Host == parsedServerURL.Host &&
		status.LastPrivateKeyHash == co.privateKeyHash()
}

// registerAccount will register a new ACME account with the server. If an
// account with the clients private key already exists, it will attempt to look
// up and verify the corresponding account, and will return that. If this fails
// due to a not found error it will register a new account with the given key.
func (co RegistryItem) Register(
	ctx context.Context,
	newFn NewClientFunc,
	acmeExternalAccountBinding *acmeapi.ExternalAccountBinding,
) (
	*cmacme.ACMEIssuerStatus,
	error,
) {
	var emailUrl string
	if co.Email != "" {
		emailUrl = fmt.Sprintf("mailto:%s", strings.ToLower(co.Email))
	}

	var contacts []string
	if emailUrl != "" {
		contacts = []string{emailUrl}
	}

	// private key, server URL and HTTP options are stored in the ACME client (cl).
	acc, err := co.getClient(newFn).Register(ctx, &acmeapi.Account{
		Contact:                contacts,
		ExternalAccountBinding: acmeExternalAccountBinding,
	}, acmeapi.AcceptTOS)
	// If the account already exists, fetch the Account object and return.
	if err == acmeapi.ErrAccountAlreadyExists {
		acc, err = co.getClient(newFn).GetReg(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("ACME GetReg operation failed: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("ACME Register operation failed: %w", err)
	}
	// TODO: re-enable this check once this field is set by Pebble
	// if acc.Status != acme.StatusValid {
	// 	return nil, fmt.Errorf("acme account is not valid")
	// }

	// if the emails are different, we update the account
	if emailUrl != "" && !slices.Contains(acc.Contact, emailUrl) {
		var err error
		acc, err = co.getClient(newFn).UpdateReg(ctx, &acmeapi.Account{
			Contact: contacts,
		})
		if err != nil {
			return nil, fmt.Errorf("ACME UpdateReg operation failed: %w", err)
		}
	}

	return &cmacme.ACMEIssuerStatus{
		URI:                 acc.URI,
		LastRegisteredEmail: co.Email,
		LastPrivateKeyHash:  co.privateKeyHash(),
	}, nil
}
