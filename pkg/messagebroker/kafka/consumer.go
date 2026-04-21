package kafka

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/IBM/sarama"
)

const (
	TopicMockNext              = "topic_mock_next"
	TopicUpload                = "topic_upload"
	TypeOfStructInMessageValue = "type_of_struct_in_value"
)

// HandlerConfig struct to define the Kafka topic and consumer group for a specific message handler
type HandlerConfig struct {
	Topic         string
	ConsumerGroup string
}

type Consumer interface {
	Start(handlerFactory func(string) sarama.ConsumerGroupHandler) error
	Close(ctx context.Context) error
}

// MessageConsumerClient ATTENTION: Start max one instance of consumer client for each service to keep resource usage low
type MessageConsumerClient struct {
	SaramaConfig *sarama.Config
	brokers      []string
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	log          *logger.Log
}

func NewConsumerClient(ctx context.Context, cfg *model.Cfg, brokers []string, log *logger.Log) (*MessageConsumerClient, error) {
	client := &MessageConsumerClient{
		SaramaConfig: commonConsumerConfig(cfg),
		brokers:      brokers,
		wg:           sync.WaitGroup{},
		log:          log,
	}

	return client, nil
}

// commonConsumerConfig returns a new Kafka consumer configuration instance with sane defaults for vc.
func commonConsumerConfig(cfg *model.Cfg) *sarama.Config {
	//TODO(mk): set cfg from file - is now hardcoded
	saramaConfig := sarama.NewConfig()
	saramaConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
	saramaConfig.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.NewBalanceStrategyRange()}
	saramaConfig.Net.SASL.Enable = false
	//TODO(mk): enable and configure security when consuming from Kafka
	return saramaConfig
}

// Start starts the actual event consuming from specified kafka topics
func (c *MessageConsumerClient) Start(ctx context.Context, handlerFactory func(string) sarama.ConsumerGroupHandler, handlerConfigs []HandlerConfig) error {
	if err := c.SaramaConfig.Validate(); err != nil {
		return err
	}

	for _, handlerConfig := range handlerConfigs {
		consumerGroup, err := sarama.NewConsumerGroup(c.brokers, handlerConfig.ConsumerGroup, c.SaramaConfig)
		if err != nil {
			c.log.Error(err, "Error creating consumer group", "group", handlerConfig.ConsumerGroup)
			return err
		}
		c.log.Info("Started consumer group", "group", handlerConfig.ConsumerGroup)

		var cancelCtx context.Context
		cancelCtx, c.cancel = context.WithCancel(ctx)

		c.wg.Add(1)
		go func(group sarama.ConsumerGroup, topic string) {
			defer c.wg.Done()
			for {
				handler := handlerFactory(topic)
				if err := group.Consume(cancelCtx, []string{topic}, handler); err != nil {
					c.log.Error(err, "Error on consumer group", "group", handlerConfig.ConsumerGroup)
					//TODO(mk): use more advanced backoff algorithm?
					time.Sleep(1 * time.Second)
				}

				if cancelCtx.Err() != nil {
					return
				}
			}
		}(consumerGroup, handlerConfig.Topic)
	}
	return nil
}

// Close closes the consumer client
func (c *MessageConsumerClient) Close(ctx context.Context) error {
	c.cancel()
	c.wg.Wait()
	c.log.Info("Stopped")
	return nil
}

// MessageHandler definition of a generic Kafka message handler
type MessageHandler interface {
	HandleMessage(ctx context.Context, message *sarama.ConsumerMessage) error
}

// ConsumerGroupHandler struct that handles Kafka group handlers
type ConsumerGroupHandler struct {
	Handlers map[string]MessageHandler
	Log      *logger.Log
}

func (cgh *ConsumerGroupHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (cgh *ConsumerGroupHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (cgh *ConsumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	if cgh.Handlers == nil {
		cgh.Log.Error(errors.New("no handlers defined"), "No Handlers for any topic")
		//TODO(mk): send to a general error topic?
		return nil
	}

	handler, exists := cgh.Handlers[claim.Topic()]
	if !exists {
		cgh.Log.Error(errors.New("no handler for topic"), "topic", claim.Topic())
		//TODO(mk): send to a general error topic?
		return nil
	}

	handlerType := reflect.TypeOf(handler).String()

	for message := range claim.Messages() {
		var errMessage string

		if err := handler.HandleMessage(session.Context(), message); err != nil {
			cgh.Log.Error(err, "Error handling message", "topic", claim.Topic())
			//TODO(mk): more advanced retry/error handling including send to error topic if not OK after X number of retries
			errMessage = fmt.Sprintf("error handling message: %v", err)
		}

		info := fmt.Sprintf("message consumed by handler type: %s, topic: %s, partition: %d, offset: %d",
			handlerType,
			claim.Topic(),
			message.Partition,
			message.Offset,
		)
		if errMessage != "" {
			info = fmt.Sprintf("%s, error: %s", info, errMessage)
		}
		cgh.Log.Debug("Consumed message", "info", info)

		session.MarkMessage(message, info)
	}
	return nil
}
