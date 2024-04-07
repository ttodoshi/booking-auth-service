package main

import (
	_ "booking-auth-service/docs"
	"booking-auth-service/internal/adapters/handler"
	"booking-auth-service/internal/adapters/repository/mongodb"
	"booking-auth-service/internal/core/servises"
	"booking-auth-service/pkg/discovery"
	"booking-auth-service/pkg/env"
	"booking-auth-service/pkg/logging"
	"github.com/gin-gonic/gin"
	"github.com/kamva/mgm/v3"
	"go.mongodb.org/mongo-driver/mongo/options"
	"os"
)

const (
	Dev  = "dev"
	Prod = "prod"
)

func init() {
	env.LoadEnvVariables()
	if os.Getenv("PROFILE") == Prod {
		gin.SetMode(gin.ReleaseMode)
	}
	discovery.InitServiceDiscovery()
}

//	@title		Auth Service API
//	@version	1.0

// @host		localhost:8090
// @BasePath	/api/v1
func main() {
	log := logging.GetLogger()

	initDatabase(log)

	r := gin.Default()
	router := initRouter(log)
	router.InitRoutes(r)

	log.Fatalf("error while running server due to: %s", r.Run())
}

func initDatabase(log logging.Logger) {
	err := mgm.SetDefaultConfig(nil, "auth", options.Client().ApplyURI(os.Getenv("DB_URL")))
	if err != nil {
		log.Fatal("failed connect to database")
	}
}

func initRouter(log logging.Logger) *handler.Router {
	refreshTokenRepository := mongodb.NewRefreshTokenRepository()
	userRepository := mongodb.NewUserRepository()

	authService := servises.NewAuthService(
		userRepository, refreshTokenRepository,
		log,
	)
	return handler.NewRouter(
		log,
		handler.NewAuthHandler(
			authService, log,
		),
	)
}
