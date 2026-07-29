package main

type AuthenticSource struct {
	ID   string `json:"id" bson:"id" validate:"required,min=1,max=20"`
	Name string `json:"name" bson:"name" validate:"required,min=1,max=100"`
}

type IssuingAuthority struct {
	ID   string `json:"id" bson:"id" validate:"required,min=1,max=20"`
	Name string `json:"name" bson:"name" validate:"required,min=1,max=100"`
}
