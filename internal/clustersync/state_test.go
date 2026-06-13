package clustersync

import (
	"testing"
	"time"

	"flowproxy/internal/settings"
)

func TestRuntimeStateFailCloseByConsecutiveFailures(t *testing.T) {
	state := NewRuntimeState(ModeFollower, settings.ClusterSync{
		CertificateSyncEnabled:       true,
		FailCloseEnabled:             true,
		FailCloseConsecutiveFailures: 2,
		FailCloseStaleAfter:          "5m",
	}, 3*time.Second)

	now := time.Now().UTC()
	state.StartAttempt(now)
	state.MarkFailure("fetch", errText("a"), now.Add(1*time.Second))
	state.StartAttempt(now.Add(2 * time.Second))
	state.MarkFailure("fetch", errText("b"), now.Add(3*time.Second))

	snapshot := state.Snapshot(now.Add(4 * time.Second))
	if !snapshot.FailCloseActive {
		t.Fatalf("expected fail-close active")
	}
	if snapshot.FailCloseReason != "consecutive_failures" {
		t.Fatalf("unexpected fail-close reason: %s", snapshot.FailCloseReason)
	}
}

func TestRuntimeStateFailCloseByStaleSync(t *testing.T) {
	state := NewRuntimeState(ModeFollower, settings.ClusterSync{
		CertificateSyncEnabled:       true,
		FailCloseEnabled:             true,
		FailCloseConsecutiveFailures: 10,
		FailCloseStaleAfter:          "30s",
	}, 3*time.Second)

	base := time.Now().UTC()
	state.StartAttempt(base)
	state.MarkSuccess(base)
	state.StartAttempt(base.Add(5 * time.Second))
	state.MarkFailure("fetch", errText("network"), base.Add(6*time.Second))

	snapshot := state.Snapshot(base.Add(40 * time.Second))
	if !snapshot.FailCloseActive {
		t.Fatalf("expected fail-close active by stale sync")
	}
	if snapshot.FailCloseReason != "stale_sync" {
		t.Fatalf("unexpected fail-close reason: %s", snapshot.FailCloseReason)
	}
}

func TestRuntimeStateMarkSuccessClearsFailClose(t *testing.T) {
	state := NewRuntimeState(ModeFollower, settings.ClusterSync{
		CertificateSyncEnabled:       true,
		FailCloseEnabled:             true,
		FailCloseConsecutiveFailures: 1,
		FailCloseStaleAfter:          "5m",
	}, 3*time.Second)

	now := time.Now().UTC()
	state.StartAttempt(now)
	state.MarkFailure("fetch", errText("network"), now.Add(time.Second))
	if !state.Snapshot(now.Add(2 * time.Second)).FailCloseActive {
		t.Fatalf("expected fail-close active after failure")
	}
	state.StartAttempt(now.Add(3 * time.Second))
	state.MarkFetchSuccess(now.Add(4 * time.Second))
	state.MarkApplySuccess(now.Add(5 * time.Second))
	state.MarkSuccess(now.Add(5 * time.Second))
	if state.Snapshot(now.Add(6 * time.Second)).FailCloseActive {
		t.Fatalf("expected fail-close to be cleared")
	}
}

func TestRuntimeStateSnapshotIncludesActiveEndpoint(t *testing.T) {
	state := NewRuntimeState(ModeFollower, settings.ClusterSync{
		CertificateSyncEnabled: true,
		FailCloseEnabled:       true,
	}, 3*time.Second)
	state.SetActiveEndpoint("https://controller-a.example.com")
	got := state.Snapshot(time.Now().UTC())
	if got.ActiveEndpoint != "https://controller-a.example.com" {
		t.Fatalf("unexpected active endpoint: %q", got.ActiveEndpoint)
	}
}

type errText string

func (e errText) Error() string { return string(e) }
