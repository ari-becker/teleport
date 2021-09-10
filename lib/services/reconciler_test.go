/*
Copyright 2021 Gravitational, Inc.

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

package services

import (
	"context"
	"testing"

	"github.com/gravitational/teleport/api/types"

	"github.com/stretchr/testify/require"
)

// TestReconciler makes sure appropriate callbacks are called during reconciliation.
func TestReconciler(t *testing.T) {
	tests := []struct {
		description         string
		selectors           []Selector
		registeredResources ResourcesWithLabels
		newResources        ResourcesWithLabels
		onCreateCalls       ResourcesWithLabels
		onUpdateCalls       ResourcesWithLabels
		onDeleteCalls       ResourcesWithLabels
	}{
		{
			description: "new matching resource should be registered",
			selectors: []Selector{{
				MatchLabels: types.Labels{"*": []string{"*"}},
			}},
			registeredResources: ResourcesWithLabels{},
			newResources: ResourcesWithLabels{
				makeDynamicResource("res1", nil),
			},
			onCreateCalls: ResourcesWithLabels{
				makeDynamicResource("res1", nil),
			},
		},
		{
			description: "new non-matching resource should not be registered",
			selectors: []Selector{{
				MatchLabels: types.Labels{"env": []string{"prod"}},
			}},
			registeredResources: ResourcesWithLabels{},
			newResources: ResourcesWithLabels{
				makeDynamicResource("res1", map[string]string{"env": "dev"}),
			},
		},
		{
			description: "resource that's no longer present should be removed",
			selectors: []Selector{{
				MatchLabels: types.Labels{"*": []string{"*"}},
			}},
			registeredResources: ResourcesWithLabels{
				makeDynamicResource("res1", nil),
			},
			newResources: ResourcesWithLabels{},
			onDeleteCalls: ResourcesWithLabels{
				makeDynamicResource("res1", nil),
			},
		},
		{
			description: "static resource should not be overwritten",
			selectors: []Selector{{
				MatchLabels: types.Labels{"*": []string{"*"}},
			}},
			registeredResources: ResourcesWithLabels{
				makeStaticResource("res1", nil),
			},
			newResources: ResourcesWithLabels{
				makeDynamicResource("res1", nil),
			},
		},
		{
			description: "resource with updated matching labels should be updated",
			selectors: []Selector{{
				MatchLabels: types.Labels{"*": []string{"*"}},
			}},
			registeredResources: ResourcesWithLabels{
				makeDynamicResource("res1", nil),
			},
			newResources: ResourcesWithLabels{
				makeDynamicResourceWithID("res1", map[string]string{"env": "dev"}, 1),
			},
			onUpdateCalls: ResourcesWithLabels{
				makeDynamicResourceWithID("res1", map[string]string{"env": "dev"}, 1),
			},
		},
		{
			description: "non-matching updated resource should be removed",
			selectors: []Selector{{
				MatchLabels: types.Labels{"env": []string{"prod"}},
			}},
			registeredResources: ResourcesWithLabels{
				makeDynamicResource("res1", map[string]string{"env": "prod"}),
			},
			newResources: ResourcesWithLabels{
				makeDynamicResourceWithID("res1", map[string]string{"env": "dev"}, 1),
			},
			onDeleteCalls: ResourcesWithLabels{
				makeDynamicResource("res1", map[string]string{"env": "prod"}),
			},
		},
		{
			description: "complex scenario with multiple created/updated/deleted resources",
			selectors: []Selector{{
				MatchLabels: types.Labels{"env": []string{"prod"}},
			}},
			registeredResources: ResourcesWithLabels{
				makeStaticResource("res0", nil),
				makeDynamicResource("res1", map[string]string{"env": "prod"}),
				makeDynamicResource("res2", map[string]string{"env": "prod"}),
				makeDynamicResource("res3", map[string]string{"env": "prod"}),
				makeDynamicResource("res4", map[string]string{"env": "prod"}),
			},
			newResources: ResourcesWithLabels{
				makeDynamicResource("res0", map[string]string{"env": "prod"}),
				makeDynamicResourceWithID("res2", map[string]string{"env": "prod", "a": "b"}, 1),
				makeDynamicResource("res3", map[string]string{"env": "prod"}),
				makeDynamicResourceWithID("res4", map[string]string{"env": "dev"}, 1),
				makeDynamicResource("res5", map[string]string{"env": "prod"}),
				makeDynamicResource("res6", map[string]string{"env": "dev"}),
			},
			onCreateCalls: ResourcesWithLabels{
				makeDynamicResource("res5", map[string]string{"env": "prod"}),
			},
			onUpdateCalls: ResourcesWithLabels{
				makeDynamicResourceWithID("res2", map[string]string{"env": "prod", "a": "b"}, 1),
			},
			onDeleteCalls: ResourcesWithLabels{
				makeDynamicResource("res1", map[string]string{"env": "prod"}),
				makeDynamicResource("res4", map[string]string{"env": "prod"}),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Reconciler will record all callback calls in these lists.
			var onCreateCalls, onUpdateCalls, onDeleteCalls ResourcesWithLabels

			reconciler, err := NewReconciler(ReconcilerConfig{
				Selectors: test.selectors,
				GetResources: func() ResourcesWithLabels {
					return test.registeredResources
				},
				OnCreate: func(ctx context.Context, r ResourceWithLabels) error {
					onCreateCalls = append(onCreateCalls, r)
					return nil
				},
				OnUpdate: func(ctx context.Context, r ResourceWithLabels) error {
					onUpdateCalls = append(onUpdateCalls, r)
					return nil
				},
				OnDelete: func(ctx context.Context, r ResourceWithLabels) error {
					onDeleteCalls = append(onDeleteCalls, r)
					return nil
				},
			})
			require.NoError(t, err)

			// Reconcile and make sure we got all expected callback calls.
			err = reconciler.Reconcile(context.Background(), test.newResources)
			require.NoError(t, err)
			require.Equal(t, test.onCreateCalls, onCreateCalls)
			require.Equal(t, test.onUpdateCalls, onUpdateCalls)
			require.Equal(t, test.onDeleteCalls, onDeleteCalls)
		})
	}
}

func makeStaticResource(name string, labels map[string]string) ResourceWithLabels {
	return makeResource(name, labels, map[string]string{
		types.OriginLabel: types.OriginConfigFile,
	}, 0)
}

func makeDynamicResource(name string, labels map[string]string) ResourceWithLabels {
	return makeResource(name, labels, map[string]string{
		types.OriginLabel: types.OriginDynamic,
	}, 0)
}

func makeDynamicResourceWithID(name string, labels map[string]string, id int64) ResourceWithLabels {
	return makeResource(name, labels, map[string]string{
		types.OriginLabel: types.OriginDynamic,
	}, id)
}

func makeResource(name string, labels map[string]string, additionalLabels map[string]string, id int64) ResourceWithLabels {
	if labels == nil {
		labels = make(map[string]string)
	}
	for k, v := range additionalLabels {
		labels[k] = v
	}
	return &testResource{
		name:   name,
		labels: labels,
		resID:  id,
	}
}

type testResource struct {
	ResourceWithLabels
	name   string
	labels map[string]string
	resID  int64
}

func (r *testResource) GetName() string {
	return r.name
}

func (r *testResource) Origin() string {
	return r.labels[types.OriginLabel]
}

func (r testResource) GetResourceID() int64 {
	return r.resID
}

func (r *testResource) GetAllLabels() map[string]string {
	return r.labels
}
