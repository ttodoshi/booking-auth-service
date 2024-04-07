package utils

import (
	"booking-auth-service/internal/core/domain"
	"booking-auth-service/internal/core/errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"strconv"
	"time"
)

var secretKey = []byte(os.Getenv("SECRET_KEY"))

func GenerateAccessJWT(user domain.User) (accessToken string, err error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	accessTokenExp, err := strconv.ParseInt(os.Getenv("ACCESS_TOKEN_EXP"), 10, 64)
	if err != nil {
		return accessToken, &errors.TokenGenerationError{
			Message: fmt.Sprintf("access token generation error due to: %s", err.Error()),
		}
	}

	claims["sub"] = user.ID.Hex()
	claims["nickname"] = user.Nickname
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Unix() + accessTokenExp

	accessToken, err = token.SignedString(secretKey)

	if err != nil {
		return accessToken, &errors.TokenGenerationError{
			Message: fmt.Sprintf("access token generation error due to: %s", err.Error()),
		}
	}
	return accessToken, nil
}

func GenerateRefreshJWT(ID string) (refreshToken string, err error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	refreshTokenExp, err := strconv.ParseInt(os.Getenv("REFRESH_TOKEN_EXP"), 10, 64)
	if err != nil {
		return refreshToken, &errors.TokenGenerationError{
			Message: fmt.Sprintf("refresh token generation error due to: %s", err.Error()),
		}
	}

	claims["sub"] = ID
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Unix() + refreshTokenExp

	refreshToken, err = token.SignedString(secretKey)

	if err != nil {
		return refreshToken, &errors.TokenGenerationError{
			Message: fmt.Sprintf("refresh token generation error due to: %s", err.Error()),
		}
	}
	return refreshToken, nil
}
