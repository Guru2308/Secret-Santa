package main

import (
	"log"
	"net/http"
)

func routers() {

	// Connect to the database and handle errors
	db, err := ConnectToDB()
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	// Serve static files from the "static" directory
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/submit-names", submitNamesHandler)

	// Login route
	http.HandleFunc("/oauth", func(w http.ResponseWriter, r *http.Request) {
		GoogleLogin(w, r)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		HandleLogin(db, w, r)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		GoogleCallback(w, r)
	})

	// Signup route
	http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		HandleSignUp(w, r) // Adjusted to call HandleSignup for signup logic
	})

	// Signup route
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		HandleLogout(w, r) // Adjusted to call HandleSignup for signup logic
	})

	// Guess route
	http.HandleFunc("/guess", func(w http.ResponseWriter, r *http.Request) {
		RequireAuth(http.HandlerFunc(HandleGuess)).ServeHTTP(w, r)
	})

	// Protected index route
	http.HandleFunc("/send-message", func(w http.ResponseWriter, r *http.Request) {
		RequireAuth(http.HandlerFunc(SecretMessageHandler)).ServeHTTP(w, r)
	})

	// http.HandleFunc("/send-message", EmailHandler)
	// Protected index route
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		RequireAuth(http.HandlerFunc(HandleIndex)).ServeHTTP(w, r)
	})
}
