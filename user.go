package main

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

func RegisterHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		password := uuid.New().String()
		salt := []byte(uuid.New().String()) // Generate a unique salt for Argon2
		passwordHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

		_, err := db.Exec("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", user.Username, passwordHash, user.Email)
		if err != nil {
			http.Error(w, "Failed to insert user into database", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"password": password})
	}
}
