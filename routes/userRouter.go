package routes

import (
	"database/sql"
	"movie-app-golang/controllers"

	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine, db *sql.DB) {
	incomingRoutes.GET("/users", controllers.GetUsers(db))
	incomingRoutes.GET("/users/:user_id", controllers.GetUser(db))
	incomingRoutes.POST("/users/signup", controllers.SignUp(db))
	incomingRoutes.POST("/users/login", controllers.Login(db))
}
