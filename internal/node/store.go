package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"flowproxy/internal/persist"
)

const (
	DefaultNodeID     = "default"
	DefaultNodeName   = "Default Node"
	ModePseudoCluster = "pseudo"

	StatusOnline   = "online"
	StatusOffline  = "offline"
	StatusDisabled = "disabled"

	DefaultHeartbeatTTL = 45 * time.Second
)

var ErrNotFound = errors.New("node not found")

type Node struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Endpoint        string    `json:"endpoint,omitempty"`
	Tags            []string  `json:"tags,omitempty"`
	Enabled         bool      `json:"enabled"`
	Mode            string    `json:"mode,omitempty"`
	LastHeartbeatAt time.Time `json:"lastHeartbeatAt,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type RuntimeNode struct {
	Node
	Status          string `json:"status"`
	IsLocal         bool   `json:"isLocal,omitempty"`
	AssignedSites   int    `json:"assignedSites"`
	AssignedEnabled int    `json:"assignedEnabledSites"`
}

type Store struct {
	mu    sync.RWMutex
	blob  persist.BlobStore
	nodes []Node
}

func New(filePath string) (*Store, error) {
	return NewWithBlob(persist.NewFileBlobStore(filePath))
}

func NewWithBlob(blob persist.BlobStore) (*Store, error) {
	if blob == nil {
		return nil, fmt.Errorf("node blob backend is required")
	}
	s := &Store{blob: blob, nodes: []Node{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func NormalizeID(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return DefaultNodeID
	}
	return value
}

func NormalizeName(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return DefaultNodeName
	}
	return value
}

func Normalize(input Node) (Node, error) {
	input.ID = NormalizeID(input.ID)
	input.Name = NormalizeName(input.Name)
	input.Endpoint = strings.TrimSpace(input.Endpoint)
	input.Mode = strings.TrimSpace(input.Mode)
	if input.Mode == "" {
		input.Mode = ModePseudoCluster
	}
	input.Tags = normalizeStringList(input.Tags)
	if input.CreatedAt.IsZero() {
		input.CreatedAt = time.Now().UTC()
	}
	if input.UpdatedAt.IsZero() {
		input.UpdatedAt = input.CreatedAt
	}
	input.CreatedAt = input.CreatedAt.UTC()
	input.UpdatedAt = input.UpdatedAt.UTC()
	input.LastHeartbeatAt = input.LastHeartbeatAt.UTC()
	return input, nil
}

func (s *Store) List() []Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Node, len(s.nodes))
	copy(out, s.nodes)
	return out
}

func (s *Store) Reload() error {
	return s.load()
}

func (s *Store) Get(id string) (Node, error) {
	key := NormalizeID(id)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.nodes {
		if item.ID == key {
			return item, nil
		}
	}
	return Node{}, ErrNotFound
}

func (s *Store) ReplaceAll(items []Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Node, 0, len(items))
	for _, item := range items {
		normalized, err := Normalize(item)
		if err != nil {
			return err
		}
		out = append(out, normalized)
	}
	s.nodes = out
	slices.SortFunc(s.nodes, func(a, b Node) int {
		return strings.Compare(a.ID, b.ID)
	})
	return s.saveLocked()
}

func (s *Store) Upsert(input Node) (Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	normalized, err := Normalize(input)
	if err != nil {
		return Node{}, err
	}
	now := time.Now().UTC()
	normalized.UpdatedAt = now

	for i, item := range s.nodes {
		if item.ID != normalized.ID {
			continue
		}
		normalized.CreatedAt = item.CreatedAt
		if normalized.LastHeartbeatAt.IsZero() {
			normalized.LastHeartbeatAt = item.LastHeartbeatAt
		}
		s.nodes[i] = normalized
		return normalized, s.saveLocked()
	}

	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = now
	}
	if normalized.LastHeartbeatAt.IsZero() {
		normalized.LastHeartbeatAt = now
	}
	s.nodes = append(s.nodes, normalized)
	slices.SortFunc(s.nodes, func(a, b Node) int {
		return strings.Compare(a.ID, b.ID)
	})
	return normalized, s.saveLocked()
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := NormalizeID(id)
	n := len(s.nodes)
	s.nodes = slices.DeleteFunc(s.nodes, func(item Node) bool {
		return item.ID == key
	})
	if len(s.nodes) == n {
		return ErrNotFound
	}
	return s.saveLocked()
}

func (s *Store) TouchHeartbeat(id string, name string, endpoint string, tags []string, enabled bool) (Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := NormalizeID(id)
	now := time.Now().UTC()
	for i, item := range s.nodes {
		if item.ID != key {
			continue
		}
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			item.Name = trimmed
		}
		if trimmed := strings.TrimSpace(endpoint); trimmed != "" {
			item.Endpoint = trimmed
		}
		if tags != nil {
			item.Tags = normalizeStringList(tags)
		}
		item.Enabled = enabled
		item.Mode = ModePseudoCluster
		item.LastHeartbeatAt = now
		item.UpdatedAt = now
		s.nodes[i] = item
		return item, s.saveLocked()
	}

	item, err := Normalize(Node{
		ID:              key,
		Name:            name,
		Endpoint:        endpoint,
		Tags:            tags,
		Enabled:         enabled,
		Mode:            ModePseudoCluster,
		LastHeartbeatAt: now,
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	if err != nil {
		return Node{}, err
	}
	s.nodes = append(s.nodes, item)
	slices.SortFunc(s.nodes, func(a, b Node) int {
		return strings.Compare(a.ID, b.ID)
	})
	return item, s.saveLocked()
}

func RuntimeStatus(item Node, now time.Time, ttl time.Duration) string {
	if !item.Enabled {
		return StatusDisabled
	}
	if ttl <= 0 {
		ttl = DefaultHeartbeatTTL
	}
	if item.LastHeartbeatAt.IsZero() {
		return StatusOffline
	}
	if now.UTC().Sub(item.LastHeartbeatAt.UTC()) <= ttl {
		return StatusOnline
	}
	return StatusOffline
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.blob.Load(context.Background())
	if err != nil {
		if persist.IsNotFound(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, &s.nodes); err != nil {
		return err
	}
	out := make([]Node, 0, len(s.nodes))
	for _, item := range s.nodes {
		normalized, err := Normalize(item)
		if err != nil {
			return fmt.Errorf("node %s validation failed: %w", item.ID, err)
		}
		out = append(out, normalized)
	}
	s.nodes = out
	slices.SortFunc(s.nodes, func(a, b Node) int {
		return strings.Compare(a.ID, b.ID)
	})
	return nil
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.nodes, "", "  ")
	if err != nil {
		return err
	}
	return s.blob.Save(context.Background(), data)
}

func normalizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}
