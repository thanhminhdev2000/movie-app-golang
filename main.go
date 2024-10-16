package main

import (
	"log"
	"movie-app-golang/database"
	"movie-app-golang/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	db, err := database.ConnectMySQL()
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}
	defer db.Close()

	router := gin.New()

	routes.UserRoutes(router, db)

	router.Run()

}
