package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	// Parse command line flags
	populatePtr := flag.Bool("populate", false, "Populate database with users from users.csv and create pairings")
	flag.Parse()

	// Load environment variables
	Loadenv()
	
	if *populatePtr {
		log.Println("Starting database population...")
		if err := PopulateDatabase("users.csv"); err != nil {
			log.Fatalf("Failed to populate database: %v", err)
		}
		return
	}

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
