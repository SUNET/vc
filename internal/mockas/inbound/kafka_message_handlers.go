package inbound

import (
	"context"
	"encoding/json"
	"vc/internal/mockas/apiv1"
	"vc/pkg/logger"
	"vc/pkg/messagebroker"
	"vc/pkg/messagebroker/kafka"
	"vc/pkg/model"
	"vc/pkg/trace"
	"vc/pkg/vcclient"

	"github.com/IBM/sarama"
)

// New creates a new Kafka event consumer instance used by mockas
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, tracer *trace.Tracer, log *logger.Log) (messagebroker.EventConsumer, error) {
	if !cfg.Common.Kafka.Enable {
		log.Info("Kafka disabled - no consumer created")
		return nil, nil
	}

	client, err := kafka.NewConsumerClient(ctx, cfg, cfg.Common.Kafka.Brokers, log.New("kafka_consumer_client"))
	if err != nil {
		return nil, err
	}

	handlerConfigs := []kafka.HandlerConfig{
		{Topic: kafka.TopicMockNext, ConsumerGroup: "topic_mock_next_consumer_group_mockas"},
		{Topic: kafka.TopicUpload, ConsumerGroup: "topic_upload_consumer_group_mockas"},
		// add more kafka.HandlerConfig here...
	}

	handlerFactory := func(topic string) sarama.ConsumerGroupHandler {
		handlersMap := map[string]kafka.MessageHandler{
			kafka.TopicMockNext: newMockNextMessageHandler(log.New("kafka_mock_next_handler"), apiv1, tracer),
			kafka.TopicUpload:   newUploadMessageHandler(log.New("kafka_upload_handler"), apiv1, tracer),
			// add more handlers here...
		}
		return &kafka.ConsumerGroupHandler{Handlers: handlersMap, Log: log.New("kafka_consumer_group_handler")}
	}

	if err := client.Start(ctx, handlerFactory, handlerConfigs); err != nil {
		return nil, err
	}
	return client, nil
}

// MockNextMessageHandler struct that handles Kafka messages of type MockNextRequest
type MockNextMessageHandler struct {
	log    *logger.Log
	apiv1  *apiv1.Client
	tracer *trace.Tracer
}

func newMockNextMessageHandler(log *logger.Log, apiv1 *apiv1.Client, tracer *trace.Tracer) *MockNextMessageHandler {
	return &MockNextMessageHandler{
		log:    log,
		apiv1:  apiv1,
		tracer: tracer,
	}
}

// HandleMessage handles Kafka message of type MockNextRequest
func (h *MockNextMessageHandler) HandleMessage(ctx context.Context, message *sarama.ConsumerMessage) error {
	var mockNextRequest vcclient.MockNextRequest
	if err := json.Unmarshal(message.Value, &mockNextRequest); err != nil {
		h.log.Error(err, "Failed to unmarshal message.Value from Kafka")
		return err
	}

	_, err := h.apiv1.MockNext(ctx, &mockNextRequest)
	if err != nil {
		h.log.Error(err, "Failed to MockNext")
		return err
	}
	return nil
}

// TODO(mk): REMOVE ME BEFORE PRODUCTION, JUST TO TEST A SECOND KAFKA CONSUMER GROUP FROM A DIFFERENT SERVICE
type UploadMessageHandler struct {
	log    *logger.Log
	apiv1  *apiv1.Client
	tracer *trace.Tracer
}

func newUploadMessageHandler(log *logger.Log, apiv1 *apiv1.Client, tracer *trace.Tracer) *UploadMessageHandler {
	return &UploadMessageHandler{
		log:    log,
		apiv1:  apiv1,
		tracer: tracer,
	}
}

func (h *UploadMessageHandler) HandleMessage(ctx context.Context, message *sarama.ConsumerMessage) error {
	h.log.Debug("Consuming message to debug", "message.Key", string(message.Key), "message.Topic", message.Topic)
	return nil
}
