package sse_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/sse"
)

func TestPublishReceive(t *testing.T) {
	b := sse.NewBroker()
	ch, unsub := b.Subscribe()
	defer unsub()

	b.Publish(sse.Event{Path: "foo.md", Hash: "abc", Action: "modified"})

	select {
	case e := <-ch:
		require.Equal(t, "foo.md", e.Path)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestUnsubscribeStopsEvents(t *testing.T) {
	b := sse.NewBroker()
	ch, unsub := b.Subscribe()
	unsub()

	b.Publish(sse.Event{Path: "foo.md", Hash: "abc", Action: "modified"})

	select {
	case _, ok := <-ch:
		require.False(t, ok, "channel should be closed")
	default:
		// also acceptable
	}
}

func TestMultipleSubscribers(t *testing.T) {
	b := sse.NewBroker()
	ch1, unsub1 := b.Subscribe()
	ch2, unsub2 := b.Subscribe()
	defer unsub1()
	defer unsub2()

	b.Publish(sse.Event{Path: "x.md", Hash: "h", Action: "modified"})

	for _, ch := range []chan sse.Event{ch1, ch2} {
		select {
		case e := <-ch:
			require.Equal(t, "x.md", e.Path)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}
}
