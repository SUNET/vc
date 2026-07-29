package kafka

import (
	"context"
	"errors"
	"fmt"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/IBM/sarama"
)

// MessageConsumerClient ATTENTION: Start max one instance of Kafka consumer client for each service to keep resource usage low
type SyncProducerClient struct {
	producer sarama.SyncProducer
	cfg      *model.Cfg
	tracer   *trace.Tracer
	log      *logger.Log
}

// NewSyncProducerClient creates a Kafka sync producer client
func NewSyncProducerClient(ctx context.Context, saramaConfig *sarama.Config, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*SyncProducerClient, error) {
	client := &SyncProducerClient{
		cfg:    cfg,
		tracer: tracer,
		log:    log,
	}

	client.log.Info("Starting ...")

	if saramaConfig == nil {
		return nil, errors.New("param saramaConfig is nil")
	}
	if err := saramaConfig.Validate(); err != nil {
		return nil, err
	}

	var err error
	client.producer, err = sarama.NewSyncProducer(cfg.Common.Kafka.Brokers, saramaConfig)
	if err != nil {
		return nil, err
	}

	client.log.Info("... started.")
	return client, nil
}

// CommonProducerConfig returns a new Kafka producer configuration instance with sane defaults for vc.
func CommonProducerConfig(cfg *model.Cfg) (*sarama.Config, error) {
	saramaConfig := sarama.NewConfig()
	saramaConfig.Producer.Return.Successes = true
	saramaConfig.Producer.RequiredAcks = sarama.WaitForAll
	saramaConfig.Producer.Idempotent = true
	saramaConfig.Net.MaxOpenRequests = 1
	saramaConfig.Producer.Retry.Max = 3

	if err := applySecurityConfig(saramaConfig, cfg); err != nil {
		return nil, err
	}

	return saramaConfig, nil
}

// Close close the producer
func (c *SyncProducerClient) Close(ctx context.Context) error {
	err := c.producer.Close()
	if err != nil {
		c.log.Error(err, "Error closing")
		return err
	}
	c.log.Info("Stopped")
	return nil
}

// PublishMessage publish a message to a Kafka topic
func (c *SyncProducerClient) PublishMessage(topic string, key string, json []byte, headers []sarama.RecordHeader) error {
	// TODO(mk): create header data in this func, ie change func def.
	message := &sarama.ProducerMessage{
		Topic:   topic,
		Key:     sarama.StringEncoder(key),
		Value:   sarama.ByteEncoder(json),
		Headers: headers,
	}

	partition, offset, err := c.producer.SendMessage(message)
	if err != nil {
		return err
	}

	c.log.Debug(fmt.Sprintf("Kafka message with key %s sent to partition %d at offset %d to topic %s\n", key, partition, offset, topic))

	return nil
}
