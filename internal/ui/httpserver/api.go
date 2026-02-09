package httpserver

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/internal/ui/apiv1"
	"vc/pkg/model"
	"vc/pkg/vcclient"
)

type Apiv1 interface {
	// ui
	Health(ctx context.Context, request *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
	Login(ctx context.Context, request *apiv1.LoginRequest) (*apiv1.LoggedinReply, error)
	Logout(ctx context.Context) error
	User(ctx context.Context) (*apiv1.LoggedinReply, error)

	// apigw
	HealthAPIGW(ctx context.Context, request *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
	DocumentList(ctx context.Context, request *vcclient.DocumentListQuery) ([]model.DocumentList, error)
	Upload(ctx context.Context, request *vcclient.UploadRequest) error
	GetDocument(ctx context.Context, request *vcclient.DocumentGetQuery) (*model.Document, error)
	Notification(ctx context.Context, reguest *vcclient.NotificationRequest) (*vcclient.NotificationReply, error)
	SearchDocuments(ctx context.Context, request *model.SearchDocumentsRequest) (*model.SearchDocumentsReply, error)
	DeleteDocument(ctx context.Context, request *vcclient.DocumentDeleteQuery) error
	AddPIDUser(ctx context.Context, request *vcclient.AddPIDRequest) error

	// mockas
	HealthMockAS(ctx context.Context, request *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
	MockNext(ctx context.Context, request *vcclient.MockNextRequest) (*vcclient.MockNextReply, error)

	// verifier
	HealthVerifier(ctx context.Context, request *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
