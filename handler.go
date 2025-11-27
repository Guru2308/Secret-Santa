package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func HandleLogin(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Validate user credentials
		var user RegisteredUser
		result := db.First(&user, "email = ?", email)

		// Check if user exists
		if result.Error != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		// Compare the hashed password with the provided password
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}

		// Generate JWT token
		// Generate JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":   user.ID,
			"email": user.Email, // Add email to claims
			"exp":   time.Now().Add(time.Hour * 24 * 30).Unix(),
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("JWTSECRET")))
		if err != nil {
			http.Error(w, "Failed to create token", http.StatusInternalServerError)
			return
		}

		// Set the token in a cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "user_email",
			Value:    tokenString,
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		// Redirect to the handleIndex function
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// If the request method is not POST, serve the login page
	tmpl, err := template.ParseFiles("static/login.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "user_email",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func HandleSignUp(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var user RegisteredUser

		// Retrieve email and password from form values
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Check if email and password are provided
		if email == "" || password == "" {
			http.Error(w, "Email and password are required", http.StatusBadRequest)
			return
		}

		// Assign email to the user struct
		user.Email = email

		// Generate a unique ID using the current Unix timestamp
		user.ID = uint(time.Now().Unix())

		// Hash the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		// Store the hashed password in the user struct
		user.Password = string(hashedPassword)

		// Save the user to the database
		result := DB.Create(&user)
		if result.Error != nil {
			// Check for duplicate email
			if result.Error.Error() == "UNIQUE constraint failed: registered_users.email" {
				http.Error(w, "User already exists", http.StatusConflict)
				return
			}
			log.Printf("Error saving user to database: %v", result.Error)
			http.Error(w, "Error saving user to database", http.StatusInternalServerError)
			return
		}

		// Redirect or send success response
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// If the request method is not POST, serve the sign-up page
	tmpl, err := template.ParseFiles("static/signup.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func HandleIndex(w http.ResponseWriter, r *http.Request) {
	// Ensure the user is authenticated
	user, ok := r.Context().Value("user").(RegisteredUser)
	if !ok {
		http.Error(w, "Unauthorized user INDEX", http.StatusUnauthorized)
		return
	}

	// Get the Santa's email (who the user is gifting to)
	santaEmail, err := getPairedUserEmail(user.ID, "santa")
	if err != nil {
		log.Printf("Error getting Santa's email: %v", err)
		http.Redirect(w, r, "static/error.html?message=Error+fetching+Santa+email", http.StatusSeeOther)
		return
	}

	// Get the Child's email (who is gifting to the user)
	childEmail, err := getPairedUserEmail(user.ID, "child")
	if err != nil {
		log.Printf("Error getting Child's email: %v", err)
		http.Redirect(w, r, "static/error.html?message=Error+fetching+Recepient+email", http.StatusSeeOther)
		return
	}

	// Extract the user's name from their email
	userName := strings.Split(user.Email, "@")[0]     // Extract the part before @
	userName = strings.ReplaceAll(userName, ".", " ") // Replace '.' with space
	userName = capitalizeWordsImproved(userName)

	// Pass the user (now with manipulated username), Santa, and Child emails to the template
	tmpl, err := template.ParseFiles("static/index.html")
	if err != nil {
		log.Printf("Error parsing index template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		User       RegisteredUser
		UserName   string
		SantaEmail string
		ChildEmail string
	}{
		User:       user,
		UserName:   userName,
		SantaEmail: santaEmail,
		ChildEmail: childEmail,
	}

	// Execute the template with the data
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func serveIndex(w http.ResponseWriter, userName, santaEmail, childEmail, errorMessage string) {
	tmpl, err := template.ParseFiles("static/index.html")
	if err != nil {
		log.Printf("Error parsing index template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		UserName     string
		SantaEmail   string
		ChildEmail   string
		ErrorMessage string
	}{
		UserName:     userName,
		SantaEmail:   santaEmail,
		ChildEmail:   childEmail,
		ErrorMessage: errorMessage,
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func HandleGuess(w http.ResponseWriter, r *http.Request) {
	// Ensure the user is authenticated
	user, ok := r.Context().Value("user").(RegisteredUser)
	if !ok {
		http.Error(w, "Unauthorized user GUESS", http.StatusUnauthorized)
		return
	}

	// Get the Santa's email (who the user is gifting to)
	santaEmail, err := getPairedUserEmail(user.ID, "santa")
	if err != nil {
		log.Printf("Error getting Santa's email: %v", err)
		http.Redirect(w, r, "static/error.html?message=Error+fetching+santa+email", http.StatusSeeOther)
		return
	}

	// Get the Child's email (who is gifting to the user)
	childEmail, err := getPairedUserEmail(user.ID, "child")
	if err != nil {
		log.Printf("Error getting Child's email: %v", err)
		http.Redirect(w, r, "static/error.html?message=Error+fetching+child+email", http.StatusSeeOther)
		return
	}

	// Extract the user's name from their email
	santaName := strings.Split(santaEmail, "@")[0]      // Extract the part before @
	santaName = strings.ReplaceAll(santaName, ".", " ") // Replace '.' with space
	santaName = capitalizeWordsImproved(santaName)

	// Extract the user's name from their email
	userName := strings.Split(user.Email, "@")[0]     // Extract the part before @
	userName = strings.ReplaceAll(userName, ".", " ") // Replace '.' with space
	userName = capitalizeWordsImproved(userName)

	// Fetch names from CSV file, excluding the current user's email
	names, err := fetchNamesFromCSV("users.csv", user.Email)
	if err != nil {
		log.Printf("Error fetching names from CSV: %v", err)
		http.Error(w, "Error fetching names", http.StatusInternalServerError)
		return
	}

	// Pass the user, manipulated username, Santa, and Child emails, and names to the template
	tmpl, err := template.ParseFiles("static/guess.html")
	if err != nil {
		log.Printf("Error parsing guess template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		User       RegisteredUser
		UserName   string
		SantaEmail string
		SantaName  string
		ChildEmail string
		NamesJSON  string
	}{
		User:       user,
		UserName:   userName,
		SantaEmail: santaEmail,
		SantaName:  santaName,
		ChildEmail: childEmail,
		NamesJSON: func() string {
			jsonData, _ := json.Marshal(names)
			return string(jsonData)
		}(),
	}

	// Execute the template with the data
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func fetchNamesFromCSV(filePath, currentUserEmail string) ([]string, error) {
	var names []string
	for record := range approvedUsers {

		//emails are in the first column
		email := record

		// Skip the current user's email
		if email == currentUserEmail {
			continue
		}

		email = strings.ReplaceAll(email, ".", " ")
		email = strings.Split(email, "@")[0]
		processedName := capitalizeWordsImproved(email)

		names = append(names, processedName)
	}

	return names, nil
}

// Function to get paired user details (email) based on role
func getPairedUserEmail(currentUserID uint, role string) (string, error) {
	var pairedUser RegisteredUser

	if role == "santa" {
		// Find who this user gives to (direct lookup)
		var connection UserConnection
		err := DB.First(&connection, "user_id = ?", currentUserID).Error
		if err != nil {
			return "", fmt.Errorf("no connections found for user with ID %d: %w", currentUserID, err)
		}

		// Fetch the recipient's email
		err = DB.First(&pairedUser, "id = ?", connection.SantaID).Error
		if err != nil {
			return "", fmt.Errorf("could not find recipient with ID %d: %w", connection.SantaID, err)
		}

	} else if role == "child" {
		// Find who gives to this user (reverse lookup: who has this user as their santa_id)
		var gifterConnection UserConnection
		err := DB.First(&gifterConnection, "santa_id = ?", currentUserID).Error
		if err != nil {
			return "", fmt.Errorf("no gifter found for user with ID %d: %w", currentUserID, err)
		}

		// Fetch the gifter's email
		err = DB.First(&pairedUser, "id = ?", gifterConnection.UserID).Error
		if err != nil {
			return "", fmt.Errorf("could not find gifter with ID %d: %w", gifterConnection.UserID, err)
		}

	} else {
		return "", fmt.Errorf("invalid role: %s. Use 'santa' or 'child'", role)
	}

	// Return the paired user's email
	return pairedUser.Email, nil
}

func capitalizeWordsImproved(input string) string {
	words := strings.Fields(input)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(string(word[0])) + strings.ToLower(word[1:])
		}
	}
	return strings.Join(words, " ")
}
