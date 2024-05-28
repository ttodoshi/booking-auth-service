package servises

import (
	"booking-auth-service/internal/core/domain"
	"booking-auth-service/internal/core/ports"
	"booking-auth-service/internal/core/ports/dto"
	"booking-auth-service/internal/core/ports/errors"
	"booking-auth-service/pkg/jwt"
	"booking-auth-service/pkg/logging"
	"booking-auth-service/pkg/password"

	"github.com/jinzhu/copier"
)

type AuthService struct {
	userRepo  ports.UserRepository
	tokenRepo ports.RefreshTokenRepository
	log       logging.Logger
}

func NewAuthService(
	userRepo ports.UserRepository,
	tokenRepo ports.RefreshTokenRepository,
	log logging.Logger,
) ports.AuthService {
	return &AuthService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		log:       log,
	}
}

func (s *AuthService) Register(
	registerRequestDto dto.RegisterRequestDto,
) (access string, refresh string, err error) {
	var user domain.User

	registerRequestDto.Password, err = password.HashPassword(registerRequestDto.Password)
	if err != nil {
		return
	}

	err = copier.Copy(&user, &registerRequestDto)
	user, err = s.userRepo.SaveUser(user)
	if err != nil {
		return
	}

	access, refresh, err = s.generateTokens(user)
	if err != nil {
		return
	}

	_, err = s.tokenRepo.SaveRefreshToken(domain.RefreshToken{
		User:  user.ID,
		Token: refresh,
	})
	return
}

func (s *AuthService) Login(
	loginRequestDto dto.LoginRequestDto,
) (access string, refresh string, err error) {
	var user domain.User
	user, err = s.userRepo.GetUserByNickname(loginRequestDto.Login)
	if err != nil {
		user, err = s.userRepo.GetUserByEmail(loginRequestDto.Login)
		if err != nil {
			return
		}
	}

	err = password.VerifyPassword(user.Password, loginRequestDto.Password)
	if err != nil {
		return access, refresh, &errors.LoginOrPasswordDoNotMatchError{
			Message: "login or password do not match",
		}
	}

	access, refresh, err = s.generateTokens(user)
	if err != nil {
		return
	}

	_, err = s.tokenRepo.SaveRefreshToken(domain.RefreshToken{
		User:  user.ID,
		Token: refresh,
	})
	return
}

func (s *AuthService) Refresh(oldRefreshToken string) (access string, refresh string, err error) {
	token, err := s.tokenRepo.GetRefreshToken(oldRefreshToken)
	if err != nil {
		return
	}

	user, _ := s.userRepo.GetUserByID(token.User.Hex())

	access, refresh, err = s.generateTokens(user)
	if err != nil {
		return
	}

	_, err = s.tokenRepo.UpdateRefreshToken(token.Token, refresh)
	return
}

func (s *AuthService) generateTokens(
	user domain.User,
) (accessToken string, refreshToken string, err error) {
	accessToken, err = jwt.GenerateAccessJWT(
		user.ID.Hex(),
		jwt.Claim{
			Name:  "nickname",
			Value: user.Nickname,
		},
	)
	refreshToken, err = jwt.GenerateRefreshJWT(user.ID.Hex())
	return
}

func (s *AuthService) Logout(refreshToken string) {
	_ = s.tokenRepo.DeleteRefreshToken(refreshToken)
}
