package utils

import (
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func CreateToken(userID int, expirationTime time.Duration) (string, error) {
	expiration := time.Now().Add(expirationTime)
	var jwtKey = []byte(os.Getenv("JWT_KEY"))

	claims := &jwt.RegisteredClaims{
		Subject:   strconv.Itoa(userID),
		ExpiresAt: jwt.NewNumericDate(expiration),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func CreateAccessToken(userID int) (string, error) {
	return CreateToken(userID, 2*time.Minute)
}

func CreateRefreshToken(userID int) (string, error) {
	return CreateToken(userID, 7*24*time.Hour)
}
