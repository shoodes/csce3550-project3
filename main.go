package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

func initDB(dbPath string) *sql.DB {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	// Create keys table
	createKeysTableSQL := `
	CREATE TABLE IF NOT EXISTS keys (
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);`
	if _, err = db.Exec(createKeysTableSQL); err != nil {
		log.Fatalf("Error creating keys table: %v", err)
	}

	// Create users table
	createUsersTableSQL := `
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		email TEXT UNIQUE,
		date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_login TIMESTAMP
	);`
	if _, err = db.Exec(createUsersTableSQL); err != nil {
		log.Fatalf("Error creating users table: %v", err)
	}

	// Create auth_logs table
	createAuthLogsTableSQL := `
	CREATE TABLE IF NOT EXISTS auth_logs(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_ip TEXT NOT NULL,
		request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER,  
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`
	if _, err = db.Exec(createAuthLogsTableSQL); err != nil {
		log.Fatalf("Error creating auth_logs table: %v", err)
	}

	return db
}

func main() {
	db := initDB("totally_not_my_privateKeys.db")
	InitializeKeyStore(db)

	r := mux.NewRouter()
	r.HandleFunc("/.well-known/jwks.json", JWKSHandler(db)).Methods("GET")
	r.HandleFunc("/auth", AuthHandler(db)).Methods("POST")
	r.HandleFunc("/register", RegisterHandler(db)).Methods("POST")

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
