package notify

import (
	"context"
	"sync"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/dustin/go-broadcast"
)

type Service struct {
	CH            map[string]broadcast.Broadcaster
	listenerCount map[string]int
	log           *logger.Log
	cfg           *model.Cfg
	mu            sync.RWMutex
}

func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		CH:            make(map[string]broadcast.Broadcaster),
		listenerCount: make(map[string]int),
		cfg:           cfg,
		log:           log.New("notify"),
	}
	return s, nil
}

func (s *Service) Notify(id string) broadcast.Broadcaster {
	b, ok := s.CH[id]
	if !ok {
		b = broadcast.NewBroadcaster(10)
		s.CH[id] = b
	}
	return b
}

func (s *Service) OpenListener(id string) chan any {
	s.mu.Lock()
	defer s.mu.Unlock()

	listener := make(chan any)
	s.Notify(id).Register(listener)
	s.listenerCount[id]++
	s.log.Debug("OpenListener", "id", id, "count", s.listenerCount[id])
	return listener
}

func (s *Service) CloseListener(id string, listener chan any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Notify(id).Unregister(listener)
	close(listener)
	s.listenerCount[id]--
	s.log.Debug("CloseListener", "id", id, "count", s.listenerCount[id])

	// Clean up if no more listeners
	if s.listenerCount[id] <= 0 {
		delete(s.listenerCount, id)
	}
}

func (s *Service) Submit(id string, msg any) {
	s.Notify(id).Submit(msg)
}

// HasListener returns true if there's an active listener for the given session ID
func (s *Service) HasListener(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count, ok := s.listenerCount[id]
	s.log.Debug("HasListener", "id", id, "ok", ok, "count", count)
	return ok && count > 0
}

func (s *Service) Close(ctx context.Context) error {
	for id, b := range s.CH {
		s.log.Debug("close broadcaster", "id", id)
		if err := b.Close(); err != nil {
			return err
		}
	}
	return nil
}
