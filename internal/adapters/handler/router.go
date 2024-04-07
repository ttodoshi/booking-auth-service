package handler

import (
	"booking-auth-service/pkg/logging"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type Router struct {
	log logging.Logger
	*AuthHandler
}

func NewRouter(log logging.Logger, authHandler *AuthHandler) *Router {
	return &Router{
		log:         log,
		AuthHandler: authHandler,
	}
}

func (r *Router) InitRoutes(e *gin.Engine) {
	r.log.Info("initializing error handling middleware")
	e.Use(ErrorHandlerMiddleware())

	r.log.Info("initializing routes")

	// swagger
	e.GET("/swagger-ui/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	apiGroup := e.Group("/api")

	v1ApiGroup := apiGroup.Group("/v1")

	v1TextsGroup := v1ApiGroup.Group("/auth")
	{
		v1TextsGroup.POST("/registration", r.Register)
		v1TextsGroup.POST("/login", r.Login)
		v1TextsGroup.GET("/refresh", r.Refresh)
		v1TextsGroup.DELETE("/logout", r.Logout)
	}
}
