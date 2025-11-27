package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"
)

func PopulateDatabase(filePath string) error {
	// 1. Connect to DB
	db, err := ConnectToDB()
	if err != nil {
		return fmt.Errorf("failed to connect to db: %v", err)
	}

	// 2. Read CSV
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open csv: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read csv: %v", err)
	}

	var emails []string
	for i, record := range records {
		if i == 0 { // Skip header
			continue
		}
		if len(record) > 0 && record[0] != "" {
			emails = append(emails, record[0])
		}
	}

	if len(emails) < 2 {
		return fmt.Errorf("need at least 2 users to pair, found %d", len(emails))
	}

	log.Printf("Found %d users in CSV", len(emails))

	// 3. Ensure users exist in DB
	var users []RegisteredUser
	for _, email := range emails {
		var user RegisteredUser
		// Try to find user
		result := db.FirstOrCreate(&user, RegisteredUser{Email: email})
		if result.Error != nil {
			log.Printf("Failed to ensure user %s: %v", email, result.Error)
			continue
		}
		users = append(users, user)
	}

	if len(users) < 2 {
		return fmt.Errorf("not enough valid users in database to pair")
	}

	// 4. Shuffle users
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(users), func(i, j int) {
		users[i], users[j] = users[j], users[i]
	})

	// 5. Create pairings (Round Robin)
	// Clear existing connections first?
	// Let's clear them to avoid conflicts or stale data
	log.Println("Clearing existing connections...")
	if err := db.Exec("DELETE FROM user_connections").Error; err != nil {
		return fmt.Errorf("failed to clear connections: %v", err)
	}

	log.Println("Creating new pairings...")
	for i := 0; i < len(users); i++ {
		currentUser := users[i]
		// Santa is the next person in the list (wrapping around)
		santaIdx := (i + 1) % len(users)
		santaUser := users[santaIdx]

		connection := UserConnection{
			UserID:  currentUser.ID,
			SantaID: santaUser.ID,
		}

		if err := db.Create(&connection).Error; err != nil {
			return fmt.Errorf("failed to create connection for %s -> %s: %v", currentUser.Email, santaUser.Email, err)
		}
		log.Printf("Paired: %s -> gives to -> %s", currentUser.Email, santaUser.Email)
	}

	log.Println("✅ Successfully populated user connections!")
	return nil
}
