package persist

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var ErrNotFound = errors.New("persist blob not found")

type BlobStore interface {
	Load(ctx context.Context) ([]byte, error)
	Save(ctx context.Context, data []byte) error
}

type FileBlobStore struct {
	path string
}

func NewFileBlobStore(path string) *FileBlobStore {
	return &FileBlobStore{path: filepath.Clean(strings.TrimSpace(path))}
}

func (s *FileBlobStore) Load(_ context.Context) ([]byte, error) {
	if _, err := os.Stat(s.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *FileBlobStore) Save(_ context.Context, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	// Atomic write: write to temp file, then rename
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.path)
}

func MarshalIndented(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
