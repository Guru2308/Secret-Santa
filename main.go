package main

import (
	"log"
	"net/http"
)

func main() {
	// Load environment variables
	Loadenv()
	InitOAuth()

	if err := LoadApprovedUsers("users.csv"); err != nil {
		log.Fatalf("Failed to load approved users: %v", err)
	}

	_, err := ConnectToDB()
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	// Sync the database
	SyncDB()

	//Calling routers
	routers()

	// Start the server
	log.Println("Server starting: https://secret-santa-488l.onrender.com/")
	err = http.ListenAndServe(":8080", nil) // Use nil to default to the standard http.DefaultServeMux
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
