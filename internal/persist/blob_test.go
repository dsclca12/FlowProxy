package persist

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestFileBlobStoreLoadSave(t *testing.T) {
	ctx := context.Background()
	store := NewFileBlobStore(filepath.Join(t.TempDir(), "state.json"))

	_, err := store.Load(ctx)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	payload := []byte(`{"ok":true}`)
	if err := store.Save(ctx, payload); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	got, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("unexpected payload: %s", string(got))
	}
}

func TestNormalizePrefix(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: "/flowproxy"},
		{in: "/", want: "/flowproxy"},
		{in: " /a/b/ ", want: "/a/b"},
	}
	for _, tt := range tests {
		if got := normalizePrefix(tt.in); got != tt.want {
			t.Fatalf("normalizePrefix(%q)=%q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeEndpoints(t *testing.T) {
	got := normalizeEndpoints([]string{" http://127.0.0.1:2379 ", "", "http://127.0.0.1:2379", "http://127.0.0.1:12379"})
	if len(got) != 2 {
		t.Fatalf("unexpected endpoints len: %d", len(got))
	}
	if got[0] != "http://127.0.0.1:2379" || got[1] != "http://127.0.0.1:12379" {
		t.Fatalf("unexpected endpoints: %#v", got)
	}
}
