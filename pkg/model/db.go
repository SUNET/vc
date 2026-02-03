package model

// OAuthUsers is the model for the OAuth users in the database
type OAuthUsers struct {
	Username        string    `json:"username" bson:"username" validate:"required"`
	Password        string    `json:"password" bson:"password" validate:"required"`
	Identity        *Identity `json:"identity" bson:"identity" validate:"required"`
	AuthenticSource string    `json:"authentic_source" bson:"authentic_source" validate:"required"`
}
