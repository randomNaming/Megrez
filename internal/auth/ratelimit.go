package auth

import (
	"sync"
	"time"
)

// 内存滑动窗口限流：单人生态，量级极小，够用且零依赖。
type limiterKey struct {
	scope string
	who   string
}

type window struct {
	start time.Time
	count int
}

type RateLimiter struct {
	mu   sync.Mutex
	win  map[limiterKey]window
	lock map[limiterKey]time.Time // 用于后台登录的连续失败锁定
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{win: make(map[limiterKey]window), lock: make(map[limiterKey]time.Time)}
}

// Allow 超过 limit 次/窗口则拒绝。
func (l *RateLimiter) Allow(scope, who string, limit int, per time.Duration) bool {
	k := limiterKey{scope, who}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.win[k]
	if !ok || now.Sub(w.start) >= per {
		l.win[k] = window{start: now, count: 1}
		return true
	}
	if w.count >= limit {
		return false
	}
	w.count++
	l.win[k] = w
	return true
}

func (l *RateLimiter) LockedOut(scope, who string) (time.Time, bool) {
	k := limiterKey{scope, who}
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.lock[k]
	if !ok {
		return time.Time{}, false
	}
	if time.Now().After(until) {
		delete(l.lock, k)
		return time.Time{}, false
	}
	return until, true
}

func (l *RateLimiter) FailLogin(scope, who string, threshold int, lockFor time.Duration) {
	k := limiterKey{scope, who}
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.win[k]
	now := time.Now()
	if !ok || now.Sub(w.start) >= 15*time.Minute {
		w = window{start: now}
	}
	w.count++
	l.win[k] = w
	if w.count >= threshold {
		l.lock[k] = now.Add(lockFor)
		w.count = 0
		l.win[k] = w
	}
}

func (l *RateLimiter) ResetLogin(scope, who string) {
	k := limiterKey{scope, who}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.win, k)
	delete(l.lock, k)
}
