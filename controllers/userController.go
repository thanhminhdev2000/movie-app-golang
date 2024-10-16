package controllers

import (
	"database/sql"
	"net/http"

	"movie-app-golang/models"
	"movie-app-golang/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func GetUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query("SELECT id, email, username FROM users ORDER BY id")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
			return
		}
		defer rows.Close()

		var users []models.UserDetail

		for rows.Next() {
			var user models.UserDetail
			if err := rows.Scan(&user.ID, &user.Email, &user.Username); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan user"})
				return
			}

			users = append(users, user)
		}

		c.JSON(http.StatusOK, gin.H{"users": users})
	}
}

func GetUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")
		row := db.QueryRow("SELECT id, email, username FROM users WHERE id = ?", userId)

		var user models.UserDetail
		if err := row.Scan(&user.ID, &user.Email, &user.Username); err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"users": user})
	}
}

func SignUp(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input models.UserSignUp

		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", input.Username).Scan(&exists)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check for existing user"})
			return
		}
		if exists {
			c.JSON(http.StatusConflict, gin.H{"error": "Username already registered"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		_, err = db.Exec("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", input.Email, input.Username, hashedPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
	}
}

func Login(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var userLogin models.UserLogin
		if err := c.ShouldBindJSON(&userLogin); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}

		var storedPassword string
		var userID int
		query := "SELECT id, password FROM users WHERE username = ?"
		err := db.QueryRow(query, userLogin.Username).Scan(&userID, &storedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database query error"})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(userLogin.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}

		token, err := utils.CreateJWT(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": token})
	}
}
