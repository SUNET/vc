package notify

import (
	"context"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newServiceForTest(t *testing.T) *Service {
	t.Helper()
	log := logger.NewSimple("test-notify")
	svc, err := New(context.Background(), &model.Cfg{}, log)
	require.NoError(t, err)
	return svc
}

// CloseListener on the last listener for an id must reclaim the
// broadcaster from the CH map. Without this an unauthenticated caller to
// /ui/notify?session_id=<random> inflates the process-wide map for the
// lifetime of the process.
func TestService_CloseListenerReclaimsBroadcaster(t *testing.T) {
	svc := newServiceForTest(t)

	listener := svc.OpenListener("session-a")
	svc.mu.Lock()
	_, present := svc.CH["session-a"]
	svc.mu.Unlock()
	require.True(t, present, "OpenListener must create the broadcaster")

	svc.CloseListener("session-a", listener)

	svc.mu.Lock()
	_, stillPresent := svc.CH["session-a"]
	count := svc.listeners["session-a"]
	svc.mu.Unlock()
	assert.False(t, stillPresent, "last CloseListener must delete the broadcaster")
	assert.Equal(t, 0, count, "listeners counter must reset after reclaim")
}

// A second concurrent listener on the same id keeps the broadcaster
// alive until the second CloseListener runs. Reclaiming prematurely
// would silently drop messages for the surviving listener.
func TestService_SecondListenerKeepsBroadcasterAlive(t *testing.T) {
	svc := newServiceForTest(t)

	a := svc.OpenListener("session-x")
	b := svc.OpenListener("session-x")

	svc.CloseListener("session-x", a)
	svc.mu.Lock()
	_, present := svc.CH["session-x"]
	count := svc.listeners["session-x"]
	svc.mu.Unlock()
	assert.True(t, present, "broadcaster must survive while another listener holds it")
	assert.Equal(t, 1, count)

	svc.CloseListener("session-x", b)
	svc.mu.Lock()
	_, present = svc.CH["session-x"]
	svc.mu.Unlock()
	assert.False(t, present, "last listener leaving must reclaim")
}

// A Submit arriving while CloseListener is reclaiming the group must not
// panic, deadlock, or send on a closed listener channel. This is the
// race the previous go-broadcast backing could not survive: Submit held
// a stale broadcaster reference whose internal goroutine had already
// stopped.
func TestService_SubmitRacesWithCloseListener(t *testing.T) {
	svc := newServiceForTest(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			listener := svc.OpenListener("race-id")
			// Drain in a goroutine so Submit never blocks on a buffer.
			drained := make(chan struct{})
			go func() {
				for range listener {
				}
				close(drained)
			}()
			svc.Submit("race-id", "msg")
			svc.CloseListener("race-id", listener)
			<-drained
		}
	}()

	for i := 0; i < 200; i++ {
		svc.Submit("race-id", "concurrent")
	}

	<-done
}

// Submit to an id with no listeners must not create an entry in the CH
// map. A stray wallet response for a session whose SSE already closed
// would otherwise leak one group per missed submit.
func TestService_SubmitWithoutListenerDoesNotLeak(t *testing.T) {
	svc := newServiceForTest(t)

	svc.Submit("ghost", "ignored")

	svc.mu.Lock()
	_, present := svc.CH["ghost"]
	svc.mu.Unlock()
	assert.False(t, present, "Submit with no listeners must not create a group entry")
}
