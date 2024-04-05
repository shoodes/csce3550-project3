package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

//const (
//authorizedKID = "AuthorizedGoodKeyID"
//)

func InitializeKeyStore(db *sql.DB) {
	generateAndStoreKey(db, time.Now().Add(1*time.Hour).Unix())  // Valid key
	generateAndStoreKey(db, time.Now().Add(-1*time.Hour).Unix()) // Expired key
}

func generateAndStoreKey(db *sql.DB, exp int64) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encrypt the privateKeyPEM before storing
	encryptedKey, err := encrypt(privateKeyPEM)
	if err != nil {
		log.Fatalf("Error encrypting key: %v", err)
	}

	_, err = db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", encryptedKey, exp)
	if err != nil {
		log.Fatalf("Error inserting key into database: %v", err)
	}
}

func JWKSHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var keys []JWK
		rows, err := db.Query("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix())
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var kid int
			var keyPEM []byte
			if err := rows.Scan(&kid, &keyPEM); err != nil {
				http.Error(w, "Failed to fetch keys", http.StatusInternalServerError)
				return
			}
			block, _ := pem.Decode(keyPEM)
			if block == nil {
				http.Error(w, "Failed to parse PEM block containing the key", http.StatusInternalServerError)
				return
			}

			pubKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				http.Error(w, "Failed to parse private key", http.StatusInternalServerError)
				return
			}
			jwk := generateJWK(pubKey.Public().(*rsa.PublicKey), strconv.Itoa(kid))
			keys = append(keys, jwk)
		}

		resp := JWKS{Keys: keys}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KID       string `json:"kid"`
	Algorithm string `json:"alg"`
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	N         string `json:"n"`
	E         string `json:"e"`
}

func generateJWK(pubKey *rsa.PublicKey, kid string) JWK {
	return JWK{
		KID:       kid,
		Algorithm: "RS256",
		KeyType:   "RSA",
		Use:       "sig",
		N:         base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}
}
