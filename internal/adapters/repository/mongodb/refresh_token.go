package mongodb

import (
	"booking-auth-service/internal/core/domain"
	"booking-auth-service/internal/core/ports"
	"booking-auth-service/internal/core/ports/errors"
	"fmt"
	"github.com/kamva/mgm/v3"
	"go.mongodb.org/mongo-driver/bson"
)

type RefreshTokenRepository struct {
}

func NewRefreshTokenRepository() ports.RefreshTokenRepository {
	return &RefreshTokenRepository{}
}

func (r *RefreshTokenRepository) GetRefreshToken(token string) (refreshToken domain.RefreshToken, err error) {
	err = mgm.Coll(&refreshToken).First(bson.M{"token": token}, &refreshToken)
	if err != nil {
		return refreshToken, &errors.RefreshError{
			Message: fmt.Sprintf("refresh token '%s' not found", token),
		}
	}
	return refreshToken, nil
}

func (r *RefreshTokenRepository) SaveRefreshToken(token domain.RefreshToken) (ID string, err error) {
	var refreshToken domain.RefreshToken
	err = mgm.Coll(&refreshToken).First(bson.M{"token": token.Token}, &refreshToken)
	if err != nil {
		err = mgm.Coll(&refreshToken).Create(&token)
		if err != nil {
			return ID, fmt.Errorf(`token not created due to error: %v`, err)
		}
		ID = token.ID.Hex()
		return ID, nil
	}
	return ID, &errors.RefreshError{
		Message: "refresh token error",
	}
}

func (r *RefreshTokenRepository) UpdateRefreshToken(oldRefreshToken, newRefreshToken string) (refreshToken domain.RefreshToken, err error) {
	refreshToken, _ = r.GetRefreshToken(oldRefreshToken)
	refreshToken.Token = newRefreshToken
	err = mgm.Coll(&refreshToken).Update(&refreshToken)
	if err != nil {
		return refreshToken, fmt.Errorf(`token not updated due to error: %v`, err)
	}
	return refreshToken, nil
}

func (r *RefreshTokenRepository) DeleteRefreshToken(token string) (err error) {
	var refreshToken domain.RefreshToken
	err = mgm.Coll(&refreshToken).First(bson.M{"token": token}, &refreshToken)
	if err != nil {
		return &errors.RefreshError{
			Message: fmt.Sprintf("refresh token '%s' not found", token),
		}
	}
	err = mgm.Coll(&refreshToken).Delete(&refreshToken)
	if err != nil {
		return fmt.Errorf(`token not deleted due to error: %v`, err)
	}
	return nil
}
