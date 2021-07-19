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

package versionchecker

import (
	"context"
	"errors"
	"io"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	rbacv1beta1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/resource"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	kubernetesscheme "k8s.io/client-go/kubernetes/scheme"

	"github.com/jetstack/cert-manager/pkg/util/versionchecker/testfixtures"
)

func manifestToObject(manifest io.Reader) ([]runtime.Object, error) {
	obj, err := resource.
		NewLocalBuilder().
		Flatten().
		Unstructured().
		Stream(manifest, "").
		Do().
		Object()
	if err != nil {
		return nil, err
	}

	list, ok := obj.(*corev1.List)
	if !ok {
		return nil, errors.New("Could not get list")
	}

	return transformObjects(list.Items)
}

func transformObjects(objects []runtime.RawExtension) ([]runtime.Object, error) {
	transformedObjects := []runtime.Object{}
	for _, resource := range objects {
		var err error
		gvk := resource.Object.GetObjectKind().GroupVersionKind()

		// Cast ClusterRole from unstructured to rbacv1 ClusterRole
		if gvk.Group == "rbac.authorization.k8s.io" && gvk.Version == "v1" && gvk.Kind == "ClusterRole" {
			unstr := resource.Object.(*unstructured.Unstructured)

			var clusterRole rbacv1.ClusterRole
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstr.Object, &clusterRole)
			if err != nil {
				return nil, err
			}

			transformedObjects = append(transformedObjects, &clusterRole)
			continue
		}

		// Cast ClusterRole from unstructured to rbacv1beta1 ClusterRole
		if gvk.Group == "rbac.authorization.k8s.io" && gvk.Version == "v1beta1" && gvk.Kind == "ClusterRole" {
			unstr := resource.Object.(*unstructured.Unstructured)

			var clusterRole rbacv1beta1.ClusterRole
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstr.Object, &clusterRole)
			if err != nil {
				return nil, err
			}

			transformedObjects = append(transformedObjects, &clusterRole)
			continue
		}

		// Create a pod for a Deployment resource
		if gvk.Group == "apps" && gvk.Version == "v1" && gvk.Kind == "Deployment" {
			unstr := resource.Object.(*unstructured.Unstructured)

			var deployment appsv1.Deployment
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstr.Object, &deployment)
			if err != nil {
				return nil, err
			}

			pod, err := GetPodFromTemplate(&deployment.Spec.Template, resource.Object, nil)
			if err != nil {
				return nil, err
			}

			transformedObjects = append(transformedObjects, pod)
		}

		transformedObjects = append(transformedObjects, resource.Object)
	}

	return transformedObjects, nil
}

func setupFakeVersionChecker(manifest io.Reader) (*versionChecker, error) {
	scheme := runtime.NewScheme()

	if err := kubernetesscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := apiextensionsv1beta1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := rbacv1beta1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	objs, err := manifestToObject(manifest)
	if err != nil {
		return nil, err
	}

	cl := fake.
		NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(objs...).
		Build()

	return &versionChecker{
		client: cl,
	}, nil
}

func TestVersionChecker(t *testing.T) {
	versions := testfixtures.ListVersions()
	if len(versions) == 0 {
		t.Fatal("did not find the test manifests")
	}

	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			f, err := testfixtures.GetManifest(version)
			if err != nil {
				t.Error(err)
			}
			defer f.Close()

			checker, err := setupFakeVersionChecker(f)
			if err != nil {
				t.Error(err)
			}

			versionGuess, err := checker.Version(context.TODO())
			if err != nil {
				t.Error(err)
			}

			if version != versionGuess {
				t.Fatalf("wrong -> expected: %s vs detected: %s", version, versionGuess)
			}
		})
	}
}
