package inbound

import (
	"context"
	"encoding/json"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/messagebroker"
	"github.com/SUNET/vc/pkg/messagebroker/kafka"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/IBM/sarama"
)

// New creates a new Kafka event consumer instance used by apigw
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
		{Topic: kafka.TopicUpload, ConsumerGroup: "topic_upload_consumer_group_apigw"},
		// add more kafka.HandlerConfig here...
	}

	handlerFactory := func(topic string) sarama.ConsumerGroupHandler {
		handlersMap := map[string]kafka.MessageHandler{
			kafka.TopicUpload: newUploadMessageHandler(log.New("kafka_upload_handler"), apiv1, tracer),
			// add more handlers here...
		}
		return &kafka.ConsumerGroupHandler{Handlers: handlersMap, Log: log.New("kafka_consumer_group_handler")}
	}

	if err := client.Start(ctx, handlerFactory, handlerConfigs); err != nil {
		return nil, err
	}
	return client, nil
}

func newUploadMessageHandler(log *logger.Log, apiv1 *apiv1.Client, tracer *trace.Tracer) *UploadMessageHandler {
	return &UploadMessageHandler{
		log:    log,
		apiv1:  apiv1,
		tracer: tracer,
	}
}

// UploadMessageHandler struct that handles Kafka messages of type UploadRequest
type UploadMessageHandler struct {
	log    *logger.Log
	apiv1  *apiv1.Client
	tracer *trace.Tracer
}

// HandleMessage handles Kafka message of type UploadRequest
func (h *UploadMessageHandler) HandleMessage(ctx context.Context, message *sarama.ConsumerMessage) error {
	var uploadRequest vcclient.UploadRequest
	if err := json.Unmarshal(message.Value, &uploadRequest); err != nil {
		h.log.Error(err, "Failed to unmarshal message.Value from Kafka")
		return err
	}

	err := h.apiv1.DatastoreUpload(ctx, &uploadRequest)
	if err != nil {
		h.log.Error(err, "Failed to handle UploadRequest")
		return err
	}
	return nil
}
