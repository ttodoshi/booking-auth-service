package jwt

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"strconv"
	"time"
)

var secretKey = []byte(os.Getenv("SECRET_KEY"))

type Claim struct {
	Name  string
	Value interface{}
}

func GenerateAccessJWT(sub string, claims ...Claim) (accessToken string, err error) {
	var accessTokenExp int64

	accessTokenExp, err = strconv.ParseInt(os.Getenv("ACCESS_TOKEN_EXP"), 10, 64)
	if err != nil {
		err = fmt.Errorf("access jwt generation error due to: %s", err.Error())
		return
	}

	accessToken, err = generateJWT(sub, accessTokenExp, claims...)

	if err != nil {
		err = fmt.Errorf("access jwt generation error due to: %s", err.Error())
		return
	}
	return
}

func GenerateRefreshJWT(sub string, claims ...Claim) (refreshToken string, err error) {
	var refreshTokenExp int64

	refreshTokenExp, err = strconv.ParseInt(os.Getenv("REFRESH_TOKEN_EXP"), 10, 64)
	if err != nil {
		err = fmt.Errorf("refresh jwt generation error due to: %s", err.Error())
		return
	}

	refreshToken, err = generateJWT(sub, refreshTokenExp, claims...)

	if err != nil {
		err = fmt.Errorf("refresh jwt generation error due to: %s", err.Error())
		return
	}
	return
}

func generateJWT(sub string, exp int64, claims ...Claim) (jwtToken string, err error) {
	token := jwt.New(jwt.SigningMethodHS256)
	tokenClaims := token.Claims.(jwt.MapClaims)

	tokenClaims["sub"] = sub
	for _, claim := range claims {
		tokenClaims[claim.Name] = claim.Value
	}
	tokenClaims["iat"] = time.Now().Unix()
	tokenClaims["exp"] = time.Now().Unix() + exp

	jwtToken, err = token.SignedString(secretKey)
	return
}
