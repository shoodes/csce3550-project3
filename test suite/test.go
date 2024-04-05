package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// URL for server
	baseURL := "http://localhost:8080/auth"

	// Test for valid JWT
	fmt.Println("Requesting valid JWT...")
	testAuthRequest(baseURL, false)

	// Test for expired JWT
	fmt.Println("Requesting expired JWT...")
	testAuthRequest(baseURL, true)

	// Test database
	fmt.Println("Checking database...")
	testDatabase("totally_not_my_privateKeys.db")
}

func testAuthRequest(baseURL string, expired bool) {
	// Username and Password for Request Body
	authPayload := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: "userABC",
		Password: "password123",
	}
	payloadBytes, err := json.Marshal(authPayload)
	if err != nil {
		fmt.Println("Error marshaling auth payload:", err)
		return
	}
	payloadBody := bytes.NewReader(payloadBytes)

	// Expired query URL
	requestURL, err := url.Parse(baseURL)
	if err != nil {
		fmt.Println("Error parsing base URL:", err)
		return
	}
	query := requestURL.Query()
	if expired {
		query.Set("expired", "true")
	}
	requestURL.RawQuery = query.Encode()

	// HTTP POST with JSON PAYLOAD
	req, err := http.NewRequest("POST", requestURL.String(), payloadBody)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// request sending logic
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	fmt.Printf("Response for expired=%t: %s\n\n", expired, body)
}

func testDatabase(dbPath string) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	// Check for keys
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		fmt.Println("Error querying database:", err)
		return
	}
	if count == 0 {
		fmt.Println("Database check failed: no keys found.")
		return
	}

	// Checking for valid/exp keys based on time
	var validKeys, expiredKeys int
	now := time.Now().Unix()
	rows, err := db.Query("SELECT exp FROM keys")
	if err != nil {
		fmt.Println("Error querying keys:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var exp int64
		if err := rows.Scan(&exp); err != nil {
			fmt.Println("Error reading key expiration:", err)
			return
		}

		if exp > now {
			validKeys++
		} else {
			expiredKeys++
		}
	}

	fmt.Printf("Database check successful: %d valid keys, %d expired keys found.\n", validKeys, expiredKeys)
}
