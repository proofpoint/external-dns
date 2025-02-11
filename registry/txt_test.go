/*
Copyright 2017 The Kubernetes Authors.

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

package registry

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/internal/testutils"
	"github.com/kubernetes-incubator/external-dns/plan"
	"github.com/kubernetes-incubator/external-dns/provider"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testZone = "test-zone.example.org"
)

func TestTXTRegistry(t *testing.T) {
	t.Run("TestNewTXTRegistry", testTXTRegistryNew)
	t.Run("TestRecords", testTXTRegistryRecords)
	t.Run("TestApplyChanges", testTXTRegistryApplyChanges)
}

func testTXTRegistryNew(t *testing.T) {
	p := provider.NewInMemoryProvider()
	_, err := NewTXTRegistry(p, "txt", "", time.Hour)
	require.Error(t, err)

	r, err := NewTXTRegistry(p, "txt", "owner", time.Hour)
	require.NoError(t, err)

	_, ok := r.mapper.(prefixNameMapper)
	require.True(t, ok)
	assert.Equal(t, "owner", r.ownerID)
	assert.Equal(t, p, r.provider)

	r, err = NewTXTRegistry(p, "", "owner", time.Hour)
	require.NoError(t, err)

	_, ok = r.mapper.(prefixNameMapper)
	assert.True(t, ok)
}

func testTXTRegistryRecords(t *testing.T) {
	t.Run("With prefix", testTXTRegistryRecordsPrefixed)
	t.Run("No prefix", testTXTRegistryRecordsNoPrefix)
}

func testTXTRegistryRecordsPrefixed(t *testing.T) {
	p := provider.NewInMemoryProvider()
	p.CreateZone(testZone)
	p.ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerAndLabels("foo.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, "", endpoint.Labels{"foo": "somefoo"}),
			newEndpointWithOwnerAndLabels("bar.test-zone.example.org", "my-domain.com", endpoint.RecordTypeCNAME, "", endpoint.Labels{"bar": "somebar"}),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "baz.test-zone.example.org", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("qux.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwnerAndLabels("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "", endpoint.Labels{"tar": "sometar"}),
			newEndpointWithOwner("TxT.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner-2\"", endpoint.RecordTypeTXT, ""), // case-insensitive TXT prefix
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-2"),
		},
	})
	expectedRecords := []*endpoint.Endpoint{
		{
			DNSName:    "foo.test-zone.example.org",
			Targets:    endpoint.Targets{"foo.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
				"foo":                  "somefoo",
			},
		},
		{
			DNSName:    "bar.test-zone.example.org",
			Targets:    endpoint.Targets{"my-domain.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
				"bar":                  "somebar",
			},
		},
		{
			DNSName:    "txt.bar.test-zone.example.org",
			Targets:    endpoint.Targets{"baz.test-zone.example.org"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			DNSName:    "qux.test-zone.example.org",
			Targets:    endpoint.Targets{"random"},
			RecordType: endpoint.RecordTypeTXT,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			DNSName:    "tar.test-zone.example.org",
			Targets:    endpoint.Targets{"tar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner-2",
				"tar":                  "sometar",
			},
		},
		{
			DNSName:    "foobar.test-zone.example.org",
			Targets:    endpoint.Targets{"foobar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			DNSName:       "multiple.test-zone.example.org",
			Targets:       endpoint.Targets{"lb1.loadbalancer.com"},
			SetIdentifier: "test-set-1",
			RecordType:    endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			DNSName:       "multiple.test-zone.example.org",
			Targets:       endpoint.Targets{"lb2.loadbalancer.com"},
			SetIdentifier: "test-set-2",
			RecordType:    endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
	}

	r, _ := NewTXTRegistry(p, "txt.", "owner", time.Hour)
	records, _ := r.Records()

	assert.True(t, testutils.SameEndpoints(records, expectedRecords))

	// Ensure prefix is case-insensitive
	r, _ = NewTXTRegistry(p, "TxT.", "owner", time.Hour)
	records, _ = r.Records()

	assert.True(t, testutils.SameEndpointLabels(records, expectedRecords))
}

func testTXTRegistryRecordsNoPrefix(t *testing.T) {
	p := provider.NewInMemoryProvider()
	p.CreateZone(testZone)
	p.ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("foo.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("bar.test-zone.example.org", "my-domain.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "baz.test-zone.example.org", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("qux.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner-2\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
		},
	})
	expectedRecords := []*endpoint.Endpoint{
		{
			DNSName:    "foo.test-zone.example.org",
			Targets:    endpoint.Targets{"foo.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			DNSName:    "bar.test-zone.example.org",
			Targets:    endpoint.Targets{"my-domain.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			DNSName:    "txt.bar.test-zone.example.org",
			Targets:    endpoint.Targets{"baz.test-zone.example.org"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey:    "owner",
				endpoint.ResourceLabelKey: "ingress/default/my-ingress",
			},
		},
		{
			DNSName:    "qux.test-zone.example.org",
			Targets:    endpoint.Targets{"random"},
			RecordType: endpoint.RecordTypeTXT,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			DNSName:    "tar.test-zone.example.org",
			Targets:    endpoint.Targets{"tar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			DNSName:    "foobar.test-zone.example.org",
			Targets:    endpoint.Targets{"foobar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
			},
		},
	}

	r, _ := NewTXTRegistry(p, "", "owner", time.Hour)
	records, _ := r.Records()

	assert.True(t, testutils.SameEndpoints(records, expectedRecords))
}

func testTXTRegistryApplyChanges(t *testing.T) {
	t.Run("With Prefix", testTXTRegistryApplyChangesWithPrefix)
	t.Run("No prefix", testTXTRegistryApplyChangesNoPrefix)
}

func testTXTRegistryApplyChangesWithPrefix(t *testing.T) {
	p := provider.NewInMemoryProvider()
	p.CreateZone(testZone)
	ctxEndpoints := []*endpoint.Endpoint{}
	ctx := context.WithValue(context.Background(), provider.RecordsContextKey, ctxEndpoints)
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		assert.Equal(t, ctxEndpoints, ctx.Value(provider.RecordsContextKey))
	}
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("foo.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("bar.test-zone.example.org", "my-domain.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "baz.test-zone.example.org", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("qux.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-2"),
		},
	})
	r, _ := NewTXTRegistry(p, "txt.", "owner", time.Hour)

	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", "", "", "ingress/default/my-ingress"),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "lb3.loadbalancer.com", "", "", "ingress/default/my-ingress").WithSetIdentifier("test-set-3"),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-1"),
		},
		UpdateNew: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("tar.test-zone.example.org", "new-tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2"),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "new.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2").WithSetIdentifier("test-set-2"),
		},
		UpdateOld: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-2"),
		},
	}
	expected := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", "", "owner", "ingress/default/my-ingress"),
			newEndpointWithOwner("txt.new-record-1.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "lb3.loadbalancer.com", "", "owner", "ingress/default/my-ingress").WithSetIdentifier("test-set-3"),
			newEndpointWithOwner("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-3"),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwner("txt.foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-1"),
		},
		UpdateNew: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("tar.test-zone.example.org", "new-tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2"),
			newEndpointWithOwner("txt.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress-2\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "new.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress-2\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-2"),
		},
		UpdateOld: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwner("txt.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-2"),
		},
	}
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		mExpected := map[string][]*endpoint.Endpoint{
			"Create":    expected.Create,
			"UpdateNew": expected.UpdateNew,
			"UpdateOld": expected.UpdateOld,
			"Delete":    expected.Delete,
		}
		mGot := map[string][]*endpoint.Endpoint{
			"Create":    got.Create,
			"UpdateNew": got.UpdateNew,
			"UpdateOld": got.UpdateOld,
			"Delete":    got.Delete,
		}
		assert.True(t, testutils.SamePlanChanges(mGot, mExpected))
		assert.Equal(t, nil, ctx.Value(provider.RecordsContextKey))
	}
	err := r.ApplyChanges(ctx, changes)
	require.NoError(t, err)
}

func testTXTRegistryApplyChangesNoPrefix(t *testing.T) {
	p := provider.NewInMemoryProvider()
	p.CreateZone(testZone)
	ctxEndpoints := []*endpoint.Endpoint{}
	ctx := context.WithValue(context.Background(), provider.RecordsContextKey, ctxEndpoints)
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		assert.Equal(t, ctxEndpoints, ctx.Value(provider.RecordsContextKey))
	}
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("foo.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("bar.test-zone.example.org", "my-domain.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "baz.test-zone.example.org", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("qux.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
		},
	})
	r, _ := NewTXTRegistry(p, "", "owner", time.Hour)

	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, ""),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
		},
		UpdateNew: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "new-tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner-2"),
		},
		UpdateOld: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner-2"),
		},
	}
	expected := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwner("new-record-1.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwner("foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
		},
		UpdateNew: []*endpoint.Endpoint{},
		UpdateOld: []*endpoint.Endpoint{},
	}
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		mExpected := map[string][]*endpoint.Endpoint{
			"Create":    expected.Create,
			"UpdateNew": expected.UpdateNew,
			"UpdateOld": expected.UpdateOld,
			"Delete":    expected.Delete,
		}
		mGot := map[string][]*endpoint.Endpoint{
			"Create":    got.Create,
			"UpdateNew": got.UpdateNew,
			"UpdateOld": got.UpdateOld,
			"Delete":    got.Delete,
		}
		assert.True(t, testutils.SamePlanChanges(mGot, mExpected))
		assert.Equal(t, nil, ctx.Value(provider.RecordsContextKey))
	}
	err := r.ApplyChanges(ctx, changes)
	require.NoError(t, err)
}

func TestCacheMethods(t *testing.T) {
	cache := []*endpoint.Endpoint{
		newEndpointWithOwner("thing.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing1.com", "1.2.3.6", "A", "owner"),
		newEndpointWithOwner("thing2.com", "1.2.3.4", "CNAME", "owner"),
		newEndpointWithOwner("thing3.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing4.com", "1.2.3.4", "A", "owner"),
	}
	registry := &TXTRegistry{
		recordsCache:  cache,
		cacheInterval: time.Hour,
	}

	expectedCacheAfterAdd := []*endpoint.Endpoint{
		newEndpointWithOwner("thing.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing1.com", "1.2.3.6", "A", "owner"),
		newEndpointWithOwner("thing2.com", "1.2.3.4", "CNAME", "owner"),
		newEndpointWithOwner("thing3.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing4.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing5.com", "1.2.3.5", "A", "owner"),
	}

	expectedCacheAfterUpdate := []*endpoint.Endpoint{
		newEndpointWithOwner("thing1.com", "1.2.3.6", "A", "owner"),
		newEndpointWithOwner("thing2.com", "1.2.3.4", "CNAME", "owner"),
		newEndpointWithOwner("thing3.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing4.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing5.com", "1.2.3.5", "A", "owner"),
		newEndpointWithOwner("thing.com", "1.2.3.6", "A", "owner2"),
	}

	expectedCacheAfterDelete := []*endpoint.Endpoint{
		newEndpointWithOwner("thing1.com", "1.2.3.6", "A", "owner"),
		newEndpointWithOwner("thing2.com", "1.2.3.4", "CNAME", "owner"),
		newEndpointWithOwner("thing3.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing4.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing5.com", "1.2.3.5", "A", "owner"),
	}
	// test add cache
	registry.addToCache(newEndpointWithOwner("thing5.com", "1.2.3.5", "A", "owner"))

	if !reflect.DeepEqual(expectedCacheAfterAdd, registry.recordsCache) {
		t.Fatalf("expected endpoints should match endpoints from cache: expected %v, but got %v", expectedCacheAfterAdd, registry.recordsCache)
	}

	// test update cache
	registry.removeFromCache(newEndpointWithOwner("thing.com", "1.2.3.4", "A", "owner"))
	registry.addToCache(newEndpointWithOwner("thing.com", "1.2.3.6", "A", "owner2"))
	// ensure it was updated
	if !reflect.DeepEqual(expectedCacheAfterUpdate, registry.recordsCache) {
		t.Fatalf("expected endpoints should match endpoints from cache: expected %v, but got %v", expectedCacheAfterUpdate, registry.recordsCache)
	}

	// test deleting a record
	registry.removeFromCache(newEndpointWithOwner("thing.com", "1.2.3.6", "A", "owner2"))
	// ensure it was deleted
	if !reflect.DeepEqual(expectedCacheAfterDelete, registry.recordsCache) {
		t.Fatalf("expected endpoints should match endpoints from cache: expected %v, but got %v", expectedCacheAfterDelete, registry.recordsCache)
	}
}

/**

helper methods

*/

func newEndpointWithOwner(dnsName, target, recordType, ownerID string) *endpoint.Endpoint {
	return newEndpointWithOwnerAndLabels(dnsName, target, recordType, ownerID, nil)
}

func newEndpointWithOwnerAndLabels(dnsName, target, recordType, ownerID string, labels endpoint.Labels) *endpoint.Endpoint {
	e := endpoint.NewEndpoint(dnsName, recordType, target)
	e.Labels[endpoint.OwnerLabelKey] = ownerID
	if labels != nil {
		for k, v := range labels {
			e.Labels[k] = v
		}
	}
	return e
}

func newEndpointWithOwnerResource(dnsName, target, recordType, ownerID, resource string) *endpoint.Endpoint {
	e := endpoint.NewEndpoint(dnsName, recordType, target)
	e.Labels[endpoint.OwnerLabelKey] = ownerID
	e.Labels[endpoint.ResourceLabelKey] = resource
	return e
}
