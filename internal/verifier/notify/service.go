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
}

func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		CH:  make(map[string]broadcast.Broadcaster),
		cfg: cfg,
		log: log.New("notify"),
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
	s.log.Debug("OpenListener", "id", id)
	return listener
}

func (s *Service) CloseListener(id string, listener chan any) {
	s.Notify(id).Unregister(listener)
	close(listener)
	s.log.Debug("CloseListener", "id", id)
}

func (s *Service) Submit(id string, msg any) {
	s.Notify(id).Submit(msg)
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
