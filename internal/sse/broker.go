package sse

import "sync"

// Event represents a file change notification sent to SSE subscribers.
type Event struct {
	Path   string `json:"path"`
	Hash   string `json:"hash"`
	Action string `json:"action"`
}

// Broker is a pub/sub hub for SSE events. It is safe for concurrent use.
type Broker struct {
	mu      sync.RWMutex
	clients map[chan Event]struct{}
}

// NewBroker returns a ready-to-use Broker.
func NewBroker() *Broker {
	return &Broker{clients: make(map[chan Event]struct{})}
}

// Subscribe registers a new subscriber and returns a buffered channel and an
// unsubscribe function. The caller must call unsubscribe when done to prevent
// a goroutine/channel leak.
func (b *Broker) Subscribe() (chan Event, func()) {
	ch := make(chan Event, 16)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()

	return ch, func() {
		b.mu.Lock()
		delete(b.clients, ch)
		b.mu.Unlock()
		close(ch)
	}
}

// Publish sends e to all current subscribers. The send is non-blocking: events
// are dropped for subscribers whose buffer is full.
func (b *Broker) Publish(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- e:
		default: // drop if subscriber is slow
		}
	}
}
