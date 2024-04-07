package domain

import (
	"github.com/kamva/mgm/v3"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	mgm.DefaultModel `bson:",inline"`
	Nickname         string `bson:"nickname"`
	Email            string `bson:"email"`
	Password         string `bson:"password"`
}

type RefreshToken struct {
	mgm.DefaultModel `bson:",inline"`
	User             primitive.ObjectID `bson:"user"`
	Token            string             `bson:"token"`
}
