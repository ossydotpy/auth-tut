package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "GET" {
		http.Error(w, "invalid request method", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "hello noob"})
}
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var RegisterDTO struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&RegisterDTO); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		log.Println(err)
		return
	}

	if strings.TrimSpace(RegisterDTO.Username) == "" || strings.TrimSpace(RegisterDTO.Password) == "" {
		http.Error(w, "username and password are required", http.StatusBadRequest)
		return
	}

	var existingUser User
	err := db.QueryRow(`SELECT username FROM users WHERE username=?`, strings.TrimSpace(RegisterDTO.Username)).Scan(&existingUser.Username)
	if err == nil {
		http.Error(w, "username already taken", http.StatusBadRequest)
		return
	} else if err != sql.ErrNoRows {
		http.Error(w, "an interna error occured", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(RegisterDTO.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "unexpected error!", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	_, err = db.Exec("Insert INTO users(username, password_hash) VALUES (?,?)", RegisterDTO.Username, string(hash))
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "user created!"})

}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "invalid request method", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		http.Error(w, "username or password can't be empty", http.StatusBadRequest)
		return
	}

	var user User
	err = db.QueryRow(
		`SELECT id, username, password_hash FROM users WHERE username=?`, req.Username).Scan(&user.ID, &user.Username, &user.PasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "invalid creds", http.StatusUnauthorized)
		} else {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			log.Println(err)
		}
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	jwtToken, err := GenerateJWT(&user)
	if err != nil {
		http.Error(w, "an internal error occured", http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": jwtToken})
}

func protectedRouteHandler(w http.ResponseWriter, r *http.Request) {
	claims := GetClaimsFromContext(r)
	if claims == nil {
		http.Error(w, "an internal error occured!", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("hello %s", claims.Username)})
}
