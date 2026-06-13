package certmgr

import (
	"path/filepath"
	"testing"
)

func TestReplaceMirroredLoadsTLSMaterial(t *testing.T) {
	tmp := t.TempDir()

	source, err := New(filepath.Join(tmp, "source", "certificates.json"), filepath.Join(tmp, "source", "certs"), Options{})
	if err != nil {
		t.Fatalf("new source manager: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })

	created, err := source.Create(Certificate{
		Type:    TypeSelfSigned,
		Domains: []string{"mirror.example.com"},
	})
	if err != nil {
		t.Fatalf("source create cert failed: %v", err)
	}
	bundle, _, _, err := source.DownloadMaterial(created.ID, "bundle", "zip", "")
	if err != nil {
		t.Fatalf("source export bundle failed: %v", err)
	}

	dest, err := New(filepath.Join(tmp, "dest", "certificates.json"), filepath.Join(tmp, "dest", "certs"), Options{})
	if err != nil {
		t.Fatalf("new dest manager: %v", err)
	}
	t.Cleanup(func() { _ = dest.Close() })

	if err := dest.ReplaceMirrored([]MirroredCertificate{
		{
			Certificate: created,
			BundleZIP:   bundle,
		},
	}); err != nil {
		t.Fatalf("replace mirrored failed: %v", err)
	}

	if _, err := dest.GetTLSCertificateByID(created.ID); err != nil {
		t.Fatalf("expected mirrored certificate to be loadable, got %v", err)
	}

	if err := dest.ReplaceMirrored(nil); err != nil {
		t.Fatalf("replace mirrored nil failed: %v", err)
	}
	if len(dest.List()) != 0 {
		t.Fatalf("expected mirrored list to be empty after replace with nil")
	}
}
