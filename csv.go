package main

import (
	"encoding/csv"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
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
	if len(req.Names) > 0 {
		parts := strings.SplitN(req.Names[0], " -> ", 2)
		if len(parts) != 2 {
			http.Error(w, "Invalid name format", http.StatusBadRequest)
			return
		}
		username := parts[0]

		// Check if the username already exists
		if existingRecords[username] {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict) // HTTP 409 Conflict
			json.NewEncoder(w).Encode(map[string]string{"message": "You have already guessed!"})
			return
		}

		// Extract only the names
		var names []string
		for _, name := range req.Names {
			parts := strings.SplitN(name, " -> ", 2)
			if len(parts) == 2 {
				names = append(names, strings.Trim(parts[1], "'"))
			}
		}

		// Write the new record
		writer := csv.NewWriter(file)
		defer writer.Flush()
		record := append([]string{username}, names...)
		if err := writer.Write(record); err != nil {
			http.Error(w, "Unable to write to CSV file", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Guesses names submitted successfully!"})
}
