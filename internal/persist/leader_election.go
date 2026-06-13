package persist

import (
	"context"
	"log"
	"path"
	"strings"
	"sync/atomic"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type LeaderElector struct {
	client    *clientv3.Client
	lockKey   string
	holderKey string
	nodeID    string
	leaseTTL  int
	onEvent   func(kind string, detail map[string]string)
}

func NewLeaderElector(client *clientv3.Client, prefix string, nodeID string, leaseTTL int) *LeaderElector {
	if leaseTTL <= 0 {
		leaseTTL = 10
	}
	key := path.Join(strings.TrimSpace(prefix), "ha", "control-plane-leader")
	if strings.HasPrefix(strings.TrimSpace(prefix), "/") {
		key = "/" + strings.TrimPrefix(key, "/")
	}
	return &LeaderElector{
		client:    client,
		lockKey:   key,
		holderKey: key + "/holder",
		nodeID:    strings.TrimSpace(nodeID),
		leaseTTL:  leaseTTL,
	}
}

func (e *LeaderElector) SetEventHook(fn func(kind string, detail map[string]string)) {
	e.onEvent = fn
}

func (e *LeaderElector) Run(ctx context.Context, isLeader *atomic.Bool) {
	if e == nil || e.client == nil || isLeader == nil {
		return
	}
	isLeader.Store(false)
	for {
		select {
		case <-ctx.Done():
			isLeader.Store(false)
			return
		default:
		}
		session, err := concurrency.NewSession(e.client, concurrency.WithTTL(e.leaseTTL), concurrency.WithContext(ctx))
		if err != nil {
			log.Printf("ha leader election session failed: %v", err)
			time.Sleep(time.Second)
			continue
		}
		mutex := concurrency.NewMutex(session, e.lockKey)
		lockCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		err = mutex.Lock(lockCtx)
		cancel()
		if err != nil {
			_ = session.Close()
			if ctx.Err() != nil {
				isLeader.Store(false)
				return
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}
		isLeader.Store(true)
		_, _ = e.client.Put(ctx, e.holderKey, e.nodeID, clientv3.WithLease(session.Lease()))
		log.Printf("ha leader acquired: key=%s node=%s", e.lockKey, e.nodeID)
		e.emit("ha_leader_acquired", map[string]string{
			"nodeId":  e.nodeID,
			"lockKey": e.lockKey,
		})
		select {
		case <-ctx.Done():
		case <-session.Done():
			log.Printf("ha leader session ended: key=%s node=%s", e.lockKey, e.nodeID)
			e.emit("ha_leader_lost", map[string]string{
				"nodeId":  e.nodeID,
				"lockKey": e.lockKey,
				"reason":  "session_done",
			})
		}
		isLeader.Store(false)
		_, _ = e.client.Delete(context.Background(), e.holderKey)
		unlockCtx, unlockCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = mutex.Unlock(unlockCtx)
		unlockCancel()
		_ = session.Close()
	}
}

func (e *LeaderElector) emit(kind string, detail map[string]string) {
	if e == nil || e.onEvent == nil {
		return
	}
	e.onEvent(kind, detail)
}

func (e *LeaderElector) CurrentLeader(ctx context.Context) (string, error) {
	if e == nil || e.client == nil {
		return "", nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resp, err := e.client.Get(ctx, e.holderKey)
	if err != nil {
		return "", err
	}
	if len(resp.Kvs) == 0 {
		return "", nil
	}
	return strings.TrimSpace(string(resp.Kvs[0].Value)), nil
}
