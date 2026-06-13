package persist

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const defaultEtcdOpTimeout = 3 * time.Second

type EtcdOptions struct {
	Endpoints   []string
	Prefix      string
	DialTimeout time.Duration
	OpTimeout   time.Duration
}

type EtcdFactory struct {
	client    *clientv3.Client
	prefix    string
	opTimeout time.Duration
}

func NewEtcdFactory(opts EtcdOptions) (*EtcdFactory, error) {
	endpoints := normalizeEndpoints(opts.Endpoints)
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("etcd endpoints are required")
	}
	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 3 * time.Second
	}
	opTimeout := opts.OpTimeout
	if opTimeout <= 0 {
		opTimeout = defaultEtcdOpTimeout
	}
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: dialTimeout,
	})
	if err != nil {
		return nil, err
	}
	return &EtcdFactory{
		client:    client,
		prefix:    normalizePrefix(opts.Prefix),
		opTimeout: opTimeout,
	}, nil
}

func (f *EtcdFactory) Close() error {
	if f == nil || f.client == nil {
		return nil
	}
	return f.client.Close()
}

func (f *EtcdFactory) Client() *clientv3.Client {
	if f == nil {
		return nil
	}
	return f.client
}

func (f *EtcdFactory) Prefix() string {
	if f == nil {
		return ""
	}
	return f.prefix
}

func (f *EtcdFactory) Blob(name string) BlobStore {
	name = strings.Trim(strings.TrimSpace(name), "/")
	key := path.Join(f.prefix, name)
	if strings.HasPrefix(f.prefix, "/") {
		key = "/" + strings.TrimPrefix(key, "/")
	}
	return &etcdBlobStore{
		client:    f.client,
		key:       key,
		opTimeout: f.opTimeout,
	}
}

type etcdBlobStore struct {
	client    *clientv3.Client
	key       string
	opTimeout time.Duration
}

func (s *etcdBlobStore) Load(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := s.opTimeout
	if timeout <= 0 {
		timeout = defaultEtcdOpTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := s.client.Get(reqCtx, s.key)
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, ErrNotFound
	}
	value := resp.Kvs[0].Value
	out := make([]byte, len(value))
	copy(out, value)
	return out, nil
}

func (s *etcdBlobStore) Save(ctx context.Context, data []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := s.opTimeout
	if timeout <= 0 {
		timeout = defaultEtcdOpTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err := s.client.Put(reqCtx, s.key, string(data))
	return err
}

func normalizeEndpoints(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizePrefix(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "/flowproxy"
	}
	value = strings.Trim(value, "/")
	if value == "" {
		return "/flowproxy"
	}
	return "/" + value
}

func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}
