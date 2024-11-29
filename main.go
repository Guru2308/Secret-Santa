package main

import (
	"log"
	"net/http"
)

func main() {
	// Load environment variables
	Loadenv()
	InitOAuth()

	if err := LoadApprovedUsers("../users.csv"); err != nil {
		log.Fatalf("Failed to load approved users: %v", err)
	}

	db, err := ConnectToDB()
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	// Sync the database
	SyncDB()

	if err = PopulateUsersFromCSV(db,"../users.csv","123"); err!=nil{
		log.Fatal("Failed to populate users from CSV")
	}

	//Calling routers
	routers()

	// Start the server
	log.Println("Server starting: https://rishay.tech/callback")
	err = http.ListenAndServe(":8080", nil) // Use nil to default to the standard http.DefaultServeMux
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
