package main

import (
	"encoding/csv"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

// Global variable to hold approved users
var approvedUsers map[string]struct{}

func LoadApprovedUsers(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	approvedUsers = make(map[string]struct{})
	for i, record := range records {
		if i == 0 {
			continue
		}
		if len(record) > 0 {
			approvedUsers[record[0]] = struct{}{}
		}
	}

	log.Println("Approved users loaded successfully")
	return nil
}

func submitNamesHandler(w http.ResponseWriter, r *http.Request) {
	var req NamesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println(err)
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	// Open the file for reading and appending
	file, err := os.OpenFile("guessed_names.csv", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		http.Error(w, "Unable to open CSV file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Read existing records to check for duplicates
	existingRecords := make(map[string]bool)
	reader := csv.NewReader(file)
	for {
		record, err := reader.Read()
		if err != nil {
			if err == csv.ErrFieldCount || err.Error() == "EOF" {
				break
			}
			http.Error(w, "Error reading CSV file", http.StatusInternalServerError)
			return
		}
		if len(record) > 0 {
			existingRecords[record[0]] = true // Assuming username is in the first column
		}
	}

	// Extract username from the first formatted name
	if len(req.Names) != 3 {
		http.Error(w, "Expected 3, got different", http.StatusBadRequest)
		return
	}
	username := req.Names[0]

	// Check if the username already exists
	if existingRecords[username] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict) // HTTP 409 Conflict
		json.NewEncoder(w).Encode(map[string]string{"message": "You have already guessed!"})
		return
	}

	// Write the new record
	writer := csv.NewWriter(file)
	defer writer.Flush()
	record := req.Names
	if err := writer.Write(record); err != nil {
		http.Error(w, "Unable to write to CSV file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Guesses names submitted successfully!"})
}
