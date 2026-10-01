package notify

import (
	"context"
	"sync"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/dustin/go-broadcast"
)

type Service struct {
	CH  map[string]broadcast.Broadcaster
	log *logger.Log
	cfg *model.Cfg
	mu  sync.Mutex

	// listeners counts active listener channels per id so CloseListener
	// can reclaim the broadcaster when the last listener for an id leaves.
	// Without this the CH map grows for the life of the process - an
	// unauthenticated /ui/notify?session_id=<random> can inflate it
	// deliberately.
	listeners map[string]int
}

func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		CH:        make(map[string]broadcast.Broadcaster),
		listeners: make(map[string]int),
		cfg:       cfg,
		log:       log.New("notify"),
	}
	return s, nil
}

func (s *Service) Notify(id string) broadcast.Broadcaster {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.CH[id]
	if !ok {
		b = broadcast.NewBroadcaster(10)
		s.CH[id] = b
	}
	return b
}

func (s *Service) OpenListener(id string) chan any {
	listener := make(chan any)
	s.Notify(id).Register(listener)
	s.mu.Lock()
	s.listeners[id]++
	s.mu.Unlock()
	s.log.Debug("OpenListener", "id", id)
	return listener
}

func (s *Service) CloseListener(id string, listener chan any) {
	s.Notify(id).Unregister(listener)
	close(listener)

	s.mu.Lock()
	s.listeners[id]--
	remaining := s.listeners[id]
	var toClose broadcast.Broadcaster
	if remaining <= 0 {
		delete(s.listeners, id)
		if b, ok := s.CH[id]; ok {
			toClose = b
			delete(s.CH, id)
		}
	}
	s.mu.Unlock()

	// Close outside the mutex: Broadcaster.Close drains its goroutine and
	// could in principle re-enter if a Submit were racing.
	if toClose != nil {
		if err := toClose.Close(); err != nil {
			s.log.Error(err, "close broadcaster", "id", id)
		}
	}
	s.log.Debug("CloseListener", "id", id, "remaining", remaining)
}

func (s *Service) Submit(id string, msg any) {
	s.Notify(id).Submit(msg)
}

func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, b := range s.CH {
		s.log.Debug("close broadcaster", "id", id)
		if err := b.Close(); err != nil {
			return err
		}
	}
	s.CH = make(map[string]broadcast.Broadcaster)
	s.listeners = make(map[string]int)
	return nil
}
