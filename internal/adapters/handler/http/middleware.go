package http

import (
	"booking-auth-service/internal/core/ports/errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

type errorResponse struct {
	Timestamp time.Time `json:"timestamp"`
	Status    int       `json:"status,omitempty"`
	Error     string    `json:"error,omitempty"`
	Message   string    `json:"message,omitempty"`
	Path      string    `json:"path,omitempty"`
}

func ErrorHandlerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			var responseStatus int
			switch err.Err.(type) {
			case *errors.BodyMappingError:
				responseStatus = http.StatusBadRequest
			case *errors.LoginOrPasswordDoNotMatchError:
				responseStatus = http.StatusBadRequest
			case *errors.CookieGettingError:
				responseStatus = http.StatusUnauthorized
			case *errors.RefreshError:
				responseStatus = http.StatusUnauthorized
			case *errors.AlreadyExistsError:
				responseStatus = http.StatusForbidden
			case *errors.NotFoundError:
				responseStatus = http.StatusNotFound
			case *errors.MappingError:
				responseStatus = http.StatusInternalServerError
			case *errors.TokenGenerationError:
				responseStatus = http.StatusInternalServerError
			case *errors.TokenParsingError:
				responseStatus = http.StatusInternalServerError
			default:
				responseStatus = http.StatusInternalServerError
			}
			c.JSON(responseStatus, errorResponse{
				Timestamp: time.Now(),
				Status:    responseStatus,
				Error:     http.StatusText(responseStatus),
				Message:   err.Err.Error(),
				Path:      c.Request.URL.Path,
			})
			c.Abort()
			return
		}
	}
}
