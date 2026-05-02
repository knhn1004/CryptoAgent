package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keys"
)

func main() {
	fmt.Printf("CryptoAgent key-service (schema v%d) listening on :8080\n", action.SchemaVersion)
	r := mux.NewRouter()
	keys.RegisterRoutes(r, keys.NewMemoryStore())
	log.Fatal(http.ListenAndServe(":8080", r))
}
