package zdns

import (
	"net"
	"reflect"
	"sync"
	"time"

	dnssrv "github.com/miekg/dns"
)

var (
	// RateLimitMax is the Number of requests before ignoring request (in RateLimitAge timeframe)
	RateLimitMax = 5
	// RateLimitAge is Time to keep message cache (and in which to count max requests)
	RateLimitAge = 2 * time.Second
	// MsgRateLimitReached is the rate limit response
	MsgRateLimitReached = "Rate Limited"
	// MsgNotCached is the not cached response
	MsgNotCached = "Not Cached"
	// MsgCached is the cached response
	MsgCached = "Cached"
)

type messageCacheDetail struct {
	Msg  dnssrv.Msg
	Date time.Time
	Hits int
}

type messageCache struct {
	sync.RWMutex
	Source map[string][]messageCacheDetail
}

var msgCache = messageCache{
	Source: make(map[string][]messageCacheDetail),
}

func init() {
	go cleanMessageCache()
}
func getMessageCache(client net.IP, msg *dnssrv.Msg) string {
	msgCache.Lock()
	defer msgCache.Unlock()
	clientString := client.String()
	for id, cache := range msgCache.Source[clientString] {
		if reflect.DeepEqual(cache.Msg.Question, msg.Question) {
			if cache.Hits > RateLimitMax {
				return MsgRateLimitReached
			}
			// we have a previously answered question
			msg.Answer = cache.Msg.Answer
			msg.Ns = cache.Msg.Ns
			msg.Extra = cache.Msg.Extra

			msg.Authoritative = cache.Msg.Authoritative
			msg.RecursionAvailable = cache.Msg.RecursionAvailable
			msgCache.Source[clientString][id].Hits++
			return MsgCached
		}
	}
	return MsgNotCached
}

func addMessageCache(client net.IP, msg *dnssrv.Msg) {
	msgCache.Lock()
	defer msgCache.Unlock()
	clientString := client.String()
	detail := messageCacheDetail{
		Msg:  *msg,
		Hits: 0,
		Date: time.Now().Add(RateLimitAge),
	}
	msgCache.Source[clientString] = append(msgCache.Source[clientString], detail)

}

func cleanMessageCache() {
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:

			msgCache.Lock()
			defer msgCache.Unlock()
			tmp := make(map[string][]messageCacheDetail)

			for ip := range msgCache.Source {
				tmp[ip] = msgCache.Source[ip]
			}

			now := time.Now()
			for ip, cache := range tmp {
				for id := len(cache); id > 1; id-- {
					if tmp[ip][id].Date.Before(now) {
						msgCache.Source[ip] = append(msgCache.Source[ip][:id], msgCache.Source[ip][id+1:]...)
					}
				}
			}
		}
	}
}
