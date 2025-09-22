package main

import (
	"database/sql"
	"net/http"

	"log"

	_ "github.com/mattn/go-sqlite3"
)

type contextKey string

const userContextKey = contextKey("user")

var SecretKey = []byte("dsfsdhhfiusdgy@#9u9")
var db *sql.DB
var err error

func main() {

	db, err = sql.Open("sqlite3", "./authy.db")

	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	_, err = db.Exec(
		`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
        )`,
	)

	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/register/", registerHandler)
	http.HandleFunc("/login/", loginHandler)
	http.Handle("/protected/", AuthMiddleware(http.HandlerFunc(protectedRouteHandler)))

	log.Println("Ready!")
	http.ListenAndServe(":8080", nil)
}
