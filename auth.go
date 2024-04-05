package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/time/rate"
)

// Create a rate limiter that allows up to 10 requests per second with a burst size of 10.
var limiter = rate.NewLimiter(rate.Every(time.Second/20), 10)

func AuthHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check the rate limiter at the very beginning of the handler.
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username, _, ok := r.BasicAuth()
		if !ok {
			var creds struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
				http.Error(w, "Invalid authentication method!", http.StatusBadRequest)
				return
			}
			username = creds.Username
		}

		expired, _ := strconv.ParseBool(r.URL.Query().Get("expired"))
		signingKey, kid, err := fetchSigningKey(db, expired)
		if err != nil {
			log.Printf("Error fetching signing key: %v", err)
			http.Error(w, "Failed to fetch key", http.StatusInternalServerError)
			return
		}

		claims := jwt.MapClaims{
			"iss": "jwks-server",
			"sub": username,
			"exp": time.Now().Add(time.Hour * 1).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid

		tokenString, err := token.SignedString(signingKey)
		if err != nil {
			http.Error(w, "Failed to sign token", http.StatusInternalServerError)
			return
		}

		// Assuming fetchUserID function is defined elsewhere and correctly retrieves the user's ID based on the username.
		userID := fetchUserID(db, username) // Only log if user is found
		if userID != 0 {
			_, err = db.Exec("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", r.RemoteAddr, userID)
			if err != nil {
				log.Printf("Failed to log auth request: %v", err) // Log the error; don't fail the request
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	}
}

func fetchUserID(db *sql.DB, username string) int {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		log.Printf("Failed to fetch user ID for username %s: %v", username, err)
		return 0
	}
	return userID
}

func fetchSigningKey(db *sql.DB, expired bool) (*rsa.PrivateKey, string, error) {
	var encryptedKeyPEM []byte
	var kid int // Use int for kid schema
	var err error

	// Adjust the SQL query as needed if you're dealing with encrypted keys.
	if expired {
		err = db.QueryRow("SELECT kid, key FROM keys WHERE exp <= ?", time.Now().Unix()).Scan(&kid, &encryptedKeyPEM)
	} else {
		err = db.QueryRow("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix()).Scan(&kid, &encryptedKeyPEM)
	}

	if err != nil {
		return nil, "", err
	}

	// Decrypt the key using the decrypt function
	decryptedKeyPEM, decryptErr := decrypt(encryptedKeyPEM)
	if decryptErr != nil {
		return nil, "", fmt.Errorf("failed to decrypt key: %v", decryptErr)
	}

	block, _ := pem.Decode(decryptedKeyPEM)
	if block == nil {
		return nil, "", errors.New("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", err
	}

	return privateKey, strconv.Itoa(kid), nil
}

func fetchKey(db *sql.DB, expired bool) (*rsa.PrivateKey, error) {
	var keyPEM []byte
	var err error

	if expired {
		err = db.QueryRow("SELECT key FROM keys WHERE exp <= ?", time.Now().Unix()).Scan(&keyPEM)
	} else {
		err = db.QueryRow("SELECT key FROM keys WHERE exp > ?", time.Now().Unix()).Scan(&keyPEM)
	}

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
