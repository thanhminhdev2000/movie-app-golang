package routes

import (
	"database/sql"
	"movie-app-golang/controllers"
	"movie-app-golang/middleware"

	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine, db *sql.DB) {
	userGroup := incomingRoutes.Group("/users")
	{
		userGroup.GET("/", middleware.AuthMiddleware(), controllers.GetUsers(db))
		userGroup.GET("/:user_id", middleware.AuthMiddleware(), controllers.GetUser(db))
		userGroup.GET("/profile", middleware.AuthMiddleware(), controllers.GetMyProfile(db))
		userGroup.POST("/signup", controllers.SignUp(db))
		userGroup.POST("/login", controllers.Login(db))
		userGroup.POST("/refresh", controllers.RefreshToken())
		userGroup.POST("/logout", controllers.Logout())
	}

}
