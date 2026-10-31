package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// 挑战只放内存：进程重启即全部失效，不留任何可重放的旧挑战。
const ChallengeTTL = 60 * time.Second

var (
	ErrChallengeNotFound = errors.New("挑战不存在或已使用")
	ErrChallengeExpired  = errors.New("挑战已过期")
	ErrChallengeMismatch = errors.New("挑战不属于该设备")
)

type challenge struct {
	DeviceID string
	Nonce    string
	Expires  time.Time
}

type ChallengeStore struct {
	mu    sync.Mutex
	items map[string]challenge
}

func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{items: make(map[string]challenge)}
}

func (s *ChallengeStore) Create(deviceID string, ttl time.Duration) (id, nonce string, err error) {
	idb := make([]byte, 24)
	nonceb := make([]byte, 32)
	if _, err := rand.Read(idb); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(nonceb); err != nil {
		return "", "", err
	}
	id = base64.RawURLEncoding.EncodeToString(idb)
	nonce = base64.RawURLEncoding.EncodeToString(nonceb)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(time.Now())
	s.items[id] = challenge{DeviceID: deviceID, Nonce: nonce, Expires: time.Now().Add(ttl)}
	return id, nonce, nil
}

// Consume 原子取出并删除：一次挑战只能用一次。
func (s *ChallengeStore) Consume(id, deviceID string, now time.Time) (nonce string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.items[id]
	if !ok {
		return "", ErrChallengeNotFound
	}
	delete(s.items, id)
	if now.After(c.Expires) {
		return "", ErrChallengeExpired
	}
	if c.DeviceID != deviceID {
		return "", ErrChallengeMismatch
	}
	return c.Nonce, nil
}

func (s *ChallengeStore) gcLocked(now time.Time) {
	for id, c := range s.items {
		if now.After(c.Expires) {
			delete(s.items, id)
		}
	}
}

// SigningPayload 是设备必须签名的原文。业务侧无需关心，客户端按同样规则拼接。
func SigningPayload(challengeID, nonce, deviceID string) []byte {
	return []byte("megrez-device-auth-v1|" + challengeID + "|" + nonce + "|" + deviceID)
}
