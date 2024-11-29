package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	oauthConfig *oauth2.Config
)

var DB *gorm.DB

func ConnectToDB() (*gorm.DB, error) {
	var err error
	dsn := os.Getenv("DB_CONN")
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	} else {
		log.Println("DB connected successfully")
	}

	// Check if the database exists before trying to create it
	createDBSQL := `SELECT 1 FROM pg_database WHERE datname = 'x'`
	var exists bool
	if err := DB.Raw(createDBSQL).Scan(&exists).Error; err != nil {
		log.Println("Error checking if database exists:", err)
		return nil, err
	}

	// Create database if it doesn't exist
	if !exists {
		createDBSQL := `CREATE DATABASE x`
		if err := DB.Exec(createDBSQL).Error; err != nil {
			log.Println("Failed to create database:", err)
			return nil, err
		}
		log.Println("Database 'x' created successfully.")
	} else {
		log.Println("Database 'x' already exists.")
	}

	return DB, nil
}

func SyncDB() {
	if err := DB.AutoMigrate(&RegisteredUser{}, &UserConnection{}); err != nil {
		log.Printf("Failed to migrate database: %v", err)
	} else {
		log.Println("Database migrated successfully.")
	}
}

func Loadenv() {
	err := godotenv.Load()
	if err != nil {
		log.Println("WARNING: Error loading .env file: ", err)
	}else{
		log.Println(".env file loaded successfully")
	}
}

func InitOAuth() {
	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}

// Login handler redirects the user to Google's OAuth consent screen
func GoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := oauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handler processes the OAuth 2.0 callback

func GoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("Failed to exchange token: %v", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Printf("Failed to fetch user info: %v", err)
		http.Error(w, "Failed to fetch user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Printf("Failed to decode user info: %v", err)
		http.Error(w, "Failed to decode user info", http.StatusInternalServerError)
		return
	}

	email, ok := userInfo["email"].(string)
	if !ok || !strings.HasSuffix(email, "@qburst.com") {
		renderUnauthorizedPage(w, "Unauthorized email: Use QBurst Mail ID")
		return
	}

	// Check if the email is in the approved list
	if !approvedUsers[email] {
		log.Printf("Email not in approved list: %s", email)
		renderUnauthorizedPage(w, "Your email is not in the approved list. Please contact the administrator.")
		return
	}

	// Save or update the user in the database
	var user RegisteredUser
	if err := DB.FirstOrCreate(&user, RegisteredUser{Email: email}).Error; err != nil {
		log.Printf("Failed to save user: %v", err)
		http.Redirect(w, r, "static/error.html?message=Failed+to+save+user", http.StatusSeeOther)
		return
	}

	// Set a cookie for user authentication
	http.SetCookie(w, &http.Cookie{
		Name:  "user_email",
		Value: email,
		Path:  "/",
	})

	// Redirect to the homepage
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Middleware to require authentication
func RequireAuth(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("user_email")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Retrieve the user from the database
		var user RegisteredUser
		if err := DB.First(&user, "email = ?", cookie.Value).Error; err != nil {
			log.Printf("User not found: %v", err)
			http.Redirect(w, r, "static/error.html?message=User+not+found", http.StatusSeeOther)
			return
		}

		// Attach user to context
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// Example protected route
func Validate(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(RegisteredUser)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": user,
	})
}
