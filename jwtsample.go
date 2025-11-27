package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	oauthConfig   *oauth2.Config
	sessionSecret []byte
)

var DB *gorm.DB

// SessionStore manages OAuth state tokens with expiration
type SessionStore struct {
	mu     sync.RWMutex
	states map[string]time.Time
}

var stateStore = &SessionStore{
	states: make(map[string]time.Time),
}

// Add stores a new state token with expiration
func (s *SessionStore) Add(state string, expiration time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state] = expiration
}

// Validate checks if a state token exists and is not expired
func (s *SessionStore) Validate(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	expiration, exists := s.states[state]
	if !exists {
		return false
	}
	
	// Check if expired
	if time.Now().After(expiration) {
		delete(s.states, state)
		return false
	}
	
	// Delete after validation (single-use)
	delete(s.states, state)
	return true
}

// Cleanup removes expired state tokens
func (s *SessionStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	now := time.Now()
	for state, expiration := range s.states {
		if now.After(expiration) {
			delete(s.states, state)
		}
	}
}

// Start periodic cleanup of expired states
func (s *SessionStore) StartCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			s.Cleanup()
		}
	}()
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SessionToken represents a signed session token
type SessionToken struct {
	Email     string `json:"email"`
	ExpiresAt int64  `json:"exp"`
}

// createSessionToken creates an HMAC-signed session token
func createSessionToken(email string) (string, error) {
	// Create token with 24-hour expiration
	token := SessionToken{
		Email:     email,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	
	// Serialize token
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	
	// Encode token
	tokenEncoded := base64.URLEncoding.EncodeToString(tokenJSON)
	
	// Create HMAC signature
	h := hmac.New(sha256.New, sessionSecret)
	h.Write([]byte(tokenEncoded))
	signature := hex.EncodeToString(h.Sum(nil))
	
	// Combine token and signature
	return fmt.Sprintf("%s.%s", tokenEncoded, signature), nil
}

// validateSessionToken validates and decodes an HMAC-signed session token
func validateSessionToken(tokenString string) (*SessionToken, error) {
	// Split token and signature
	parts := strings.Split(tokenString, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}
	
	tokenEncoded := parts[0]
	providedSignature := parts[1]
	
	// Verify HMAC signature
	h := hmac.New(sha256.New, sessionSecret)
	h.Write([]byte(tokenEncoded))
	expectedSignature := hex.EncodeToString(h.Sum(nil))
	
	if !hmac.Equal([]byte(expectedSignature), []byte(providedSignature)) {
		return nil, fmt.Errorf("invalid signature")
	}
	
	// Decode token
	tokenJSON, err := base64.URLEncoding.DecodeString(tokenEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}
	
	// Deserialize token
	var token SessionToken
	if err := json.Unmarshal(tokenJSON, &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}
	
	// Check expiration
	if time.Now().Unix() > token.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}
	
	return &token, nil
}

func ConnectToDB() (*gorm.DB, error) {
	var err error
	dsn := os.Getenv("DB_CONN")
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	} else {
		log.Println("DB connected successfully")
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
	} else {
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
	
	// Load session secret
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		log.Fatal("SESSION_SECRET environment variable is required")
	}
	sessionSecret = []byte(secret)
	
	// Start state store cleanup
	stateStore.StartCleanup()
}

// Login handler redirects the user to Google's OAuth consent screen
func GoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate cryptographically secure random state token
	state, err := generateSecureToken()
	if err != nil {
		log.Printf("Failed to generate state token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Store state with 10-minute expiration
	stateStore.Add(state, time.Now().Add(10*time.Minute))
	
	// Generate OAuth URL with secure state
	url := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handler processes the OAuth 2.0 callback
func GoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Validate state parameter (CSRF protection)
	state := r.URL.Query().Get("state")
	if state == "" {
		log.Printf("OAuth callback missing state parameter")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	if !stateStore.Validate(state) {
		log.Printf("Invalid or expired OAuth state: %s", state)
		http.Error(w, "Invalid or expired session", http.StatusBadRequest)
		return
	}
	
	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("Failed to exchange token: %v", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Printf("Failed to fetch user info: %v", err)
		http.Error(w, "Failed to fetch user information", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Printf("Failed to decode user info: %v", err)
		http.Error(w, "Failed to process user information", http.StatusInternalServerError)
		return
	}

	email, ok := userInfo["email"].(string)
	if !ok || !strings.HasSuffix(email, "@qburst.com") {
		http.Redirect(w, r, "static/error.html?message=Use+only+QB+Email", http.StatusSeeOther)
		return
	}

	// Check if the email is in the approved list
	if _, ok := approvedUsers[email]; !ok {
		log.Printf("Email not in approved list: %s", email)
		http.Redirect(w, r, "static/error.html?message=You+have+not+registered+for+the+game", http.StatusSeeOther)
		return
	}

	// Save or update the user in the database
	var user RegisteredUser
	if err := DB.FirstOrCreate(&user, RegisteredUser{Email: email}).Error; err != nil {
		log.Printf("Failed to save user: %v", err)
		http.Redirect(w, r, "static/error.html?message=Failed+to+save+user", http.StatusSeeOther)
		return
	}

	// Create signed session token
	sessionToken, err := createSessionToken(email)
	if err != nil {
		log.Printf("Failed to create session token: %v", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set secure cookie with signed token
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,                                              // Prevents XSS attacks
		Secure:   os.Getenv("ENVIRONMENT") != "development",         // Requires HTTPS in production only
		SameSite: http.SameSiteLaxMode,                              // Lax allows OAuth redirects, still prevents CSRF
		MaxAge:   24 * 60 * 60,                                      // 24 hours
	})

	log.Printf("✅ Session cookie set for user: %s (Secure=%v)", email, os.Getenv("ENVIRONMENT") != "development")

	// Redirect to the homepage
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Middleware to require authentication
func RequireAuth(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session token from cookie
		cookie, err := r.Cookie("session_token")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Validate and decode signed token
		token, err := validateSessionToken(cookie.Value)
		if err != nil {
			log.Printf("Invalid session token: %v", err)
			// Clear invalid cookie
			http.SetCookie(w, &http.Cookie{
				Name:   "session_token",
				Value:  "",
				Path:   "/",
				MaxAge: -1,
			})
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Retrieve the user from the database
		var user RegisteredUser
		if err := DB.First(&user, "email = ?", token.Email).Error; err != nil {
			log.Printf("User not found in database: %v", err)
			http.Redirect(w, r, "static/error.html?message=User+not+found", http.StatusSeeOther)
			return
		}

		// Attach user to context
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// HTTPS enforcement middleware
func EnforceHTTPS(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip HTTPS enforcement in development
		if os.Getenv("ENVIRONMENT") == "development" {
			next.ServeHTTP(w, r)
			return
		}

		// Check if request is over HTTPS
		if r.Header.Get("X-Forwarded-Proto") != "https" && r.TLS == nil {
			// Redirect to HTTPS
			httpsURL := "https://" + r.Host + r.RequestURI
			http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
			return
		}

		// Add HSTS header
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
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
