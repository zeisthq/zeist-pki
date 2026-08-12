package kubernetes

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/zeisthq/zeist-pki/rotation"
)

func TestLockerTakesExpiredLeaseAndRejectsCurrentHolder(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	duration := int32(60)
	foreign := "foreign"
	expired := metav1.NewMicroTime(now.Add(-61 * time.Second))
	client := fake.NewSimpleClientset(&coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: "zeist-pki-webhook", Namespace: "system"},
		Spec:       coordinationv1.LeaseSpec{HolderIdentity: &foreign, LeaseDurationSeconds: &duration, RenewTime: &expired},
	})
	locker := Locker{Client: client, Namespace: "system", Identity: "worker-a", Duration: time.Minute, RenewInterval: 30 * time.Second, Now: func() time.Time { return now }}
	raw, err := locker.Acquire(context.Background(), "webhook")
	if err != nil {
		t.Fatalf("acquire expired lease: %v", err)
	}
	lock := raw.(*Lock)
	defer func() { _ = lock.Release(context.Background()) }()
	lease, err := client.CoordinationV1().Leases("system").Get(context.Background(), "zeist-pki-webhook", metav1.GetOptions{})
	if err != nil || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "worker-a" || lease.Spec.RenewTime == nil || !lease.Spec.RenewTime.Time.Equal(now) {
		t.Fatalf("acquired lease = %#v, %v", lease, err)
	}

	current := metav1.NewMicroTime(now.Add(-time.Second))
	lease.Spec.HolderIdentity = &foreign
	lease.Spec.RenewTime = &current
	if _, err := client.CoordinationV1().Leases("system").Update(context.Background(), lease, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := locker.Acquire(context.Background(), "webhook"); err == nil || !strings.Contains(err.Error(), "is held") {
		t.Fatalf("acquire current foreign lease = %v, want held error", err)
	}
}

func TestLockerRejectsReentrantAcquisitionWithTheSameIdentity(t *testing.T) {
	client := fake.NewSimpleClientset()
	locker := Locker{Client: client, Namespace: "system", Identity: "pod:shared-process", Duration: time.Minute, RenewInterval: 30 * time.Second}
	raw, err := locker.Acquire(context.Background(), "webhook")
	if err != nil {
		t.Fatalf("first acquisition: %v", err)
	}
	defer func() { _ = raw.Release(context.Background()) }()
	if _, err := locker.Acquire(context.Background(), "webhook"); err == nil || !strings.Contains(err.Error(), "is held") {
		t.Fatalf("reentrant same-identity acquisition = %v, want held error", err)
	}
}

func TestLockHeartbeatRenewsHeldLease(t *testing.T) {
	client := fake.NewSimpleClientset()
	renewed := make(chan *coordinationv1.Lease, 1)
	client.PrependReactor("update", "leases", func(action k8stesting.Action) (bool, runtime.Object, error) {
		update, ok := action.(k8stesting.UpdateAction)
		if !ok {
			return false, nil, nil
		}
		lease, ok := update.GetObject().(*coordinationv1.Lease)
		if !ok {
			return false, nil, nil
		}
		select {
		case renewed <- lease.DeepCopy():
		default:
		}
		return false, nil, nil
	})
	locker := Locker{Client: client, Namespace: "system", Identity: "worker-a", Duration: time.Second, RenewInterval: time.Millisecond}
	raw, err := locker.Acquire(context.Background(), "webhook")
	if err != nil {
		t.Fatal(err)
	}
	lock := raw.(*Lock)
	defer func() { _ = lock.Release(context.Background()) }()
	select {
	case lease := <-renewed:
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "worker-a" || lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil || *lease.Spec.LeaseDurationSeconds != 1 {
			t.Fatalf("renewed lease = %#v", lease)
		}
	case <-time.After(time.Second):
		t.Fatal("lease heartbeat did not renew")
	}
	if err := lock.Err(); err != nil {
		t.Fatalf("healthy lock err = %v", err)
	}
}

func TestLockHeartbeatCancelsContextOnRenewalConflict(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("update", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, "zeist-pki-webhook", errors.New("simulated concurrent writer"))
	})
	locker := Locker{Client: client, Namespace: "system", Identity: "worker-a", Duration: time.Second, RenewInterval: time.Millisecond}
	raw, err := locker.Acquire(context.Background(), "webhook")
	if err != nil {
		t.Fatal(err)
	}
	lock := raw.(*Lock)
	defer func() { _ = lock.Release(context.Background()) }()
	select {
	case <-lock.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("renewal conflict did not cancel the lock context")
	}
	if err := lock.Err(); !errors.Is(err, rotation.ErrConflict) {
		t.Fatalf("lock error = %v, want wrapped ErrConflict", err)
	}
}

func TestLockReleaseDoesNotTurnExpectedCancellationIntoFenceLoss(t *testing.T) {
	client := fake.NewSimpleClientset()
	renewalStarted := make(chan struct{})
	allowRenewalReturn := make(chan struct{})
	var updates atomic.Int32
	client.PrependReactor("update", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		if updates.Add(1) != 1 {
			return false, nil, nil
		}
		close(renewalStarted)
		<-allowRenewalReturn
		return true, nil, context.Canceled
	})
	locker := Locker{Client: client, Namespace: "system", Identity: "worker-a", Duration: time.Second, RenewInterval: time.Millisecond}
	raw, err := locker.Acquire(context.Background(), "webhook")
	if err != nil {
		t.Fatal(err)
	}
	lock := raw.(*Lock)
	select {
	case <-renewalStarted:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not start renewal")
	}

	released := make(chan error, 1)
	go func() { released <- lock.Release(context.Background()) }()
	deadline := time.After(time.Second)
	for {
		lock.mu.RLock()
		stopping := lock.stopping
		lock.mu.RUnlock()
		if stopping {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Release() did not begin stopping the heartbeat")
		case <-time.After(time.Millisecond):
		}
	}
	close(allowRenewalReturn)
	select {
	case err := <-released:
		if err != nil {
			t.Fatalf("Release() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Release() did not drain heartbeat")
	}
	if err := lock.Err(); err != nil {
		t.Fatalf("normal Release() recorded renewal loss: %v", err)
	}
}
