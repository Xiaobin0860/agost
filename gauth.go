package gost

import (
	"bufio"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-log/log"
)

var instance *GlobalAuthenticator

func GetGlobalAuthenticator() *GlobalAuthenticator {
	return instance
}

func InitGlobalAuthenticator(s string) {
	f, err := os.Open(s)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	instance = NewGlobalAuthenticator(nil, nil)
	instance.Reload(f)

	go PeriodReload(instance, s)
}

// GlobalAuthenticator is an Authenticator that authenticates client by local key-value pairs.
type GlobalAuthenticator struct {
	kvs     map[string]string
	ips     map[string]struct{}
	period  time.Duration
	stopped chan struct{}
	mux     sync.RWMutex
}

// NewGlobalAuthenticator creates an Authenticator that authenticates client by local infos.
func NewGlobalAuthenticator(kvs map[string]string, ips map[string]struct{}) *GlobalAuthenticator {
	return &GlobalAuthenticator{
		kvs:     kvs,
		ips:     ips,
		stopped: make(chan struct{}),
	}
}

// Authenticate checks the validity of the provided user-password pair.
func (au *GlobalAuthenticator) Authenticate(user, password string) bool {
	au.mux.RLock()
	defer au.mux.RUnlock()

	if len(au.kvs) == 0 {
		// 全局认证需要调这个方法说明一定要验证，无账密配置说明有本ip白名单，也算不通过
		return false
	}

	v, ok := au.kvs[user]
	return ok && (v == "" || password == v)
}
func (au *GlobalAuthenticator) Auth(user, password, ip string) bool {
	au.mux.RLock()
	defer au.mux.RUnlock()

	has_ip := false
	if len(au.ips) > 0 {
		has_ip = true
		if _, ok := au.ips[ip]; ok {
			//ip白名单
			return true
		}
	}

	if !has_ip && len(au.kvs) == 0 {
		//认证配置都没有，算通过
		return true
	}

	//认证账密
	v, ok := au.kvs[user]
	return ok && (v == "" || password == v)
}
func (au *GlobalAuthenticator) IsWhite(ip string) (bool, bool) {
	au.mux.RLock()
	defer au.mux.RUnlock()

	has_ip := false
	if len(au.ips) > 0 {
		has_ip = true
		_, ok := au.ips[ip]
		return ok, true
	}

	return false, has_ip || len(au.kvs) > 0
}

// Add adds a key-value pair to the Authenticator.
func (au *GlobalAuthenticator) Add(k, v string) {
	au.mux.Lock()
	defer au.mux.Unlock()
	if au.kvs == nil {
		au.kvs = make(map[string]string)
	}
	au.kvs[k] = v
}

// Reload parses config from r, then live reloads the Authenticator.
func (au *GlobalAuthenticator) Reload(r io.Reader) error {
	var period time.Duration
	kvs := make(map[string]string)

	if r == nil || au.Stopped() {
		return nil
	}

	// splitLine splits a line text by white space.
	// A line started with '#' will be ignored, otherwise it is valid.
	split := func(line string) []string {
		if line == "" {
			return nil
		}
		line = strings.Replace(line, "\t", " ", -1)
		line = strings.TrimSpace(line)

		if strings.IndexByte(line, '#') == 0 {
			return nil
		}

		var ss []string
		for _, s := range strings.Split(line, " ") {
			if s = strings.TrimSpace(s); s != "" {
				ss = append(ss, s)
			}
		}
		return ss
	}

	ips := make(map[string]struct{})
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		ss := split(line)
		if len(ss) == 0 {
			continue
		}

		switch ss[0] {
		case "reload": // reload option
			if len(ss) > 1 {
				period, _ = time.ParseDuration(ss[1])
			}
		case "$IP$": // white ip
			ips[ss[1]] = struct{}{}
		default:
			var k, v string
			k = ss[0]
			if len(ss) > 1 {
				v = ss[1]
			}
			kvs[k] = v
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if Debug {
		log.Logf("GAuth reloaded: %d kv, %d ip", len(kvs), len(ips))
	}

	au.mux.Lock()
	defer au.mux.Unlock()

	au.period = period
	au.kvs = kvs
	au.ips = ips

	return nil
}

// Period returns the reload period.
func (au *GlobalAuthenticator) Period() time.Duration {
	if au.Stopped() {
		return -1
	}

	au.mux.RLock()
	defer au.mux.RUnlock()

	return au.period
}

// Stop stops reloading.
func (au *GlobalAuthenticator) Stop() {
	select {
	case <-au.stopped:
	default:
		close(au.stopped)
	}
}

// Stopped checks whether the reloader is stopped.
func (au *GlobalAuthenticator) Stopped() bool {
	select {
	case <-au.stopped:
		return true
	default:
		return false
	}
}

func (au *GlobalAuthenticator) HasAuth() bool {
	au.mux.RLock()
	defer au.mux.RUnlock()

	return len(au.kvs) > 0 || len(au.ips) > 0
}

func (au *GlobalAuthenticator) HasKvs() bool {
	au.mux.RLock()
	defer au.mux.RUnlock()

	return len(au.kvs) > 0
}
