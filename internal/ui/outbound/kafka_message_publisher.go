package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"vc/internal/ui/apiv1"
	"vc/pkg/logger"
	"vc/pkg/messagebroker/kafka"
	"vc/pkg/model"
	"vc/pkg/trace"
	"vc/pkg/vcclient"

	"github.com/IBM/sarama"
)

type kafkaMessageProducer struct {
	client *kafka.SyncProducerClient
}

// New creates a new instance of a kafka event publisher used by ui
func New(ctx context.Context, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (apiv1.EventPublisher, error) {
	saramaConfig := kafka.CommonProducerConfig(cfg)
	client, err := kafka.NewSyncProducerClient(ctx, saramaConfig, cfg, tracer, log.New("kafka_message_producer_client"))
	if err != nil {
		return nil, err
	}
	return &kafkaMessageProducer{
		client: client,
	}, nil
}

// MockNext publish a MockNext message to a Kafka topic
func (s *kafkaMessageProducer) MockNext(mockNextRequest *vcclient.MockNextRequest) error {
	if mockNextRequest == nil {
		return errors.New("param mockNextRequest is nil")
	}

	jsonMarshaled, err := json.Marshal(mockNextRequest)
	if err != nil {
		return err
	}

	//TODO(mk): make header code below generic and move to kafka client
	paramType := reflect.TypeFor[vcclient.MockNextRequest]().Name()
	typeHeader := []byte(paramType)
	headers := []sarama.RecordHeader{
		{Key: []byte(kafka.TypeOfStructInMessageValue), Value: typeHeader},
	}

	//TODO(mk): use other key than mockNextRequest.AuthenticSourcePersonID to also support mock using eIDAS attributes
	return s.client.PublishMessage(kafka.TopicMockNext, mockNextRequest.AuthenticSourcePersonID, jsonMarshaled, headers)
}

// Close closes all resources used/started by the publisher
func (s *kafkaMessageProducer) Close(ctx context.Context) error {
	if s.client != nil {
		return s.client.Close(ctx)
	}
	return nil
}
