package handler

import (
	"booking-auth-service/internal/adapters/dto"
	"booking-auth-service/internal/core/errors"
	"booking-auth-service/internal/core/ports"
	"booking-auth-service/pkg/logging"
	"fmt"
	"github.com/gin-gonic/gin"
	"os"
	"strconv"
)

type AuthHandler struct {
	svc ports.AuthService
	log logging.Logger
}

func NewAuthHandler(svc ports.AuthService, log logging.Logger) *AuthHandler {
	return &AuthHandler{
		svc: svc,
		log: log,
	}
}

// Register godoc
//
//	@Summary		Register new user
//	@Description	Register new user
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		dto.RegisterRequestDto	true	"Register request"
//	@Success		201		{object}	dto.AuthResponseDto
//	@Header			200		{string}	refreshToken	"token"
//	@Router			/auth/registration [post]
func (h *AuthHandler) Register(c *gin.Context) {
	h.log.Debug("received register request")

	sessionCookie, err := c.Cookie("SESSION")
	var registerRequestDto dto.RegisterRequestDto
	if err = c.ShouldBindJSON(&registerRequestDto); err != nil {
		err = c.Error(&errors.BodyMappingError{
			Message: "error in request body",
		})
		h.log.Warn("error in request body")
		return
	}

	access, refresh, err := h.svc.Register(registerRequestDto, sessionCookie)
	if err != nil {
		err = c.Error(err)
		return
	}

	refreshTokenExp, err := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXP"))
	if err != nil {
		err = c.Error(&errors.TokenGenerationError{
			Message: fmt.Sprintf("refresh token generation error due to: %s", err.Error()),
		})
		return
	}

	c.SetCookie("refreshToken", refresh, refreshTokenExp, "/", os.Getenv("COOKIE_HOST"), false, true)
	c.JSON(201, dto.AuthResponseDto{
		Access:  access,
		Refresh: refresh,
	})
}

// Login godoc
//
//	@Summary		Login
//	@Description	Login
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		dto.LoginRequestDto	true	"Login request"
//	@Success		200		{object}	dto.AuthResponseDto
//	@Header			200		{string}	refreshToken	"token"
//	@Router			/auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	h.log.Debug("received login request")

	sessionCookie, err := c.Cookie("SESSION")
	var loginRequestDto dto.LoginRequestDto
	if err = c.ShouldBindJSON(&loginRequestDto); err != nil {
		err = c.Error(&errors.BodyMappingError{
			Message: "error in request body",
		})
		h.log.Warn("error in request body")
		return
	}

	access, refresh, err := h.svc.Login(loginRequestDto, sessionCookie)
	if err != nil {
		err = c.Error(err)
		return
	}

	refreshTokenExp, err := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXP"))
	if err != nil {
		err = c.Error(&errors.TokenGenerationError{
			Message: fmt.Sprintf("refresh token generation error due to: %s", err.Error()),
		})
		return
	}

	c.SetCookie("refreshToken", refresh, refreshTokenExp, "/", os.Getenv("COOKIE_HOST"), false, true)
	c.JSON(200, dto.AuthResponseDto{
		Access:  access,
		Refresh: refresh,
	})
}

// Refresh godoc
//
//	@Summary		Refresh
//	@Description	Refresh
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			refreshToken	header		string	true	"Refresh token"
//	@Success		200				{object}	dto.AuthResponseDto
//	@Header			200				{string}	refreshToken	"token"
//	@Router			/auth/refresh [get]
func (h *AuthHandler) Refresh(c *gin.Context) {
	h.log.Debug("received refresh request")

	refreshTokenCookie, err := c.Cookie("refreshToken")
	if err != nil || refreshTokenCookie == "" {
		err = c.Error(&errors.CookieGettingError{
			Message: "error while getting refresh token cookie",
		})
		h.log.Warn("error while getting refreshTokenCookie")
		return
	}

	access, refresh, err := h.svc.Refresh(refreshTokenCookie)
	if err != nil {
		err = c.Error(err)
		return
	}

	refreshTokenExp, err := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXP"))
	if err != nil {
		err = c.Error(&errors.TokenGenerationError{
			Message: fmt.Sprintf("refresh token generation error due to: %s", err.Error()),
		})
		return
	}

	c.SetCookie("refreshToken", refresh, refreshTokenExp, "/", os.Getenv("COOKIE_HOST"), false, true)
	c.JSON(200, dto.AuthResponseDto{
		Access:  access,
		Refresh: refresh,
	})
}

// Logout godoc
//
//	@Summary		Logout
//	@Description	Logout
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			refreshToken	header	string	true	"Refresh token"
//	@Success		204
//	@Router			/auth/logout [delete]
func (h *AuthHandler) Logout(c *gin.Context) {
	h.log.Debug("received logout request")

	refreshTokenCookie, err := c.Cookie("refreshToken")
	if err != nil || refreshTokenCookie == "" {
		err = c.Error(&errors.CookieGettingError{
			Message: "error while getting refresh token cookie",
		})
		h.log.Warn("error while getting refreshTokenCookie")
		return
	}

	h.svc.Logout(refreshTokenCookie)

	c.SetCookie("refreshToken", "", -1, "/", os.Getenv("COOKIE_HOST"), false, true)
	c.Status(204)
}
