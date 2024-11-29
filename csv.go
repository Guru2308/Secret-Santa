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
var approvedUsers map[string]bool

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

	approvedUsers = make(map[string]bool)
	for _, record := range records {
		if len(record) > 0 {
			approvedUsers[record[0]] = true
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

	// Open the file for appending or create it if it doesn't exist
	file, err := os.OpenFile("guessed_names.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Unable to open CSV file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Check if the file is empty to write headers (optional)
	_, err = file.Stat()
	if err != nil {
		http.Error(w, "Unable to read CSV file info", http.StatusInternalServerError)
		return
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Extract username from the first formatted name (assuming it's consistent)
	if len(req.Names) > 0 {
		// Split the username and the first name from the formatted string
		parts := strings.SplitN(req.Names[0], " -> ", 2)
		if len(parts) != 2 {
			http.Error(w, "Invalid name format", http.StatusBadRequest)
			return
		}

		username := parts[0]
		// Extract only the names (strip the username part)
		var names []string
		for _, name := range req.Names {
			parts := strings.SplitN(name, " -> ", 2)
			if len(parts) == 2 {
				// Remove quotes around the name
				names = append(names, strings.Trim(parts[1], "'"))
			}
		}

		// Write the row with the username followed by names
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