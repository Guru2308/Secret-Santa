package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
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


const (
	spreadsheetID = "1mpiC5oUjGB6rJBDcIyjmkoVhwvnr_d73tUGwQP_LFZw" 
	sheetName     = "Guessed_List"
)

func submitNamesHandler(w http.ResponseWriter, r *http.Request) {
	var req NamesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println(err)
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	// Extract username from the first formatted name
	if len(req.Names) != 3 {
		http.Error(w, "Expected 3 names, got different", http.StatusBadRequest)
		return
	}
	username := req.Names[0]

	// Authenticate and create the Sheets service
	ctx := context.Background()
	srv, err := sheets.NewService(ctx, option.WithCredentialsFile("credentials.json"))
	if err != nil {
		log.Printf("Unable to create Sheets service: %v", err)
		http.Error(w, "Unable to access Google Sheets", http.StatusInternalServerError)
		return
	}

	// Read existing records to check for duplicates
	readRange := sheetName + "!A:A" 
	resp, err := srv.Spreadsheets.Values.Get(spreadsheetID, readRange).Do()
	if err != nil {
		log.Printf("Unable to read from Google Sheets: %v", err)
		http.Error(w, "Error reading Google Sheets", http.StatusInternalServerError)
		return
	}

	existingRecords := make(map[string]bool)
	for _, row := range resp.Values {
		if len(row) > 0 {
			existingRecords[row[0].(string)] = true
		}
	}

	// Check if the username already exists
	if existingRecords[username] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict) // HTTP 409 Conflict
		json.NewEncoder(w).Encode(map[string]string{"message": "You have already guessed!"})
		return
	}

	// Append the new record to the Google Sheet
	writeRange := sheetName + "!A:C" 
	_, err = srv.Spreadsheets.Values.Append(spreadsheetID, writeRange, &sheets.ValueRange{
		Values: [][]interface{}{{
			req.Names[0], req.Names[1], req.Names[2],
		}},
	}).ValueInputOption("RAW").Do()
	if err != nil {
		log.Printf("Unable to write to Google Sheets: %v", err)
		http.Error(w, "Unable to write to Google Sheets", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Guesses names submitted successfully!"})
}
