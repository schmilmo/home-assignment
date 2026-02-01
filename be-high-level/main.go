package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// TokenData stores token metadata
type TokenData struct {
	CreatedAt time.Time
}

// AppState holds all application state
type AppState struct {
	mu          sync.RWMutex
	tokens      map[string]TokenData
	dailyWins   int
	lastResetDay string
}

var state = &AppState{
	tokens:    make(map[string]TokenData),
	dailyWins: 0,
}

// Request/Response structures
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type LogoutResponse struct {
	Status string `json:"status"`
}

type TryLuckResponse struct {
	Win bool `json:"win"`
}

// Helper functions
func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func generateToken() string {
	return uuid.New().String()
}

func getCurrentDay() string {
	return time.Now().Format("2006-01-02")
}

func resetDailyWinsIfNeeded() {
	state.mu.Lock()
	defer state.mu.Unlock()

	currentDay := getCurrentDay()
	if state.lastResetDay != currentDay {
		state.dailyWins = 0
		state.lastResetDay = currentDay
		log.Println("Daily wins reset for new day")
	}
}

func calculateWin() bool {
	state.mu.RLock()
	defer state.mu.RUnlock()

	var winRate float64
	if state.dailyWins >= 30 {
		winRate = 0.4
	} else {
		winRate = 0.7
	}

	return rand.Float64() < winRate
}

func incrementDailyWins() {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.dailyWins++
}

func getDailyWins() int {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.dailyWins
}

func tokenExists(token string) bool {
	state.mu.RLock()
	defer state.mu.RUnlock()
	_, exists := state.tokens[token]
	return exists
}

func addToken(token string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.tokens[token] = TokenData{CreatedAt: time.Now()}
}

func removeToken(token string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	delete(state.tokens, token)
}

func getTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	return parts[1], nil
}

// Endpoint handlers
func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid request body"})
		return
	}

	// Validate email
	if !isValidEmail(req.Email) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid email"})
		return
	}

	// Validate password
	if req.Password != "r2isthebest" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid password"})
		return
	}

	// Generate token
	token := generateToken()
	addToken(token)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LoginResponse{Token: token})
	log.Printf("Login successful for email: %s, token: %s", req.Email, token)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token, err := getTokenFromHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
		return
	}

	if !tokenExists(token) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid token"})
		return
	}

	removeToken(token)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LogoutResponse{Status: "OK"})
	log.Printf("Logout successful for token: %s", token)
}

func handleTryLuck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token, err := getTokenFromHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
		return
	}

	if !tokenExists(token) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid token"})
		return
	}

	// Check and reset daily wins if needed
	resetDailyWinsIfNeeded()

	// Calculate win
	won := calculateWin()

	if won {
		incrementDailyWins()
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(TryLuckResponse{Win: won})
	log.Printf("Try luck for token: %s, result: %v, daily wins: %d", token, won, getDailyWins())
}

func main() {
	// Initialize random seed
	rand.Seed(time.Now().UnixNano())

	// Initialize daily wins tracking
	state.lastResetDay = getCurrentDay()

	// Create router
	router := mux.NewRouter()

	// Register handlers
	router.HandleFunc("/api/login", handleLogin).Methods("POST")
	router.HandleFunc("/api/logout", handleLogout).Methods("POST")
	router.HandleFunc("/api/try_luck", handleTryLuck).Methods("POST")

	// Start server
	port := "4000"
	log.Printf("Starting backend server on port %s", port)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}