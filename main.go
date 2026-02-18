package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"dumptcp/internal/engine"
	"dumptcp/internal/handlers"
)

func main() {
	port := flag.Int("port", 8080, "HTTP server port")
	flag.Parse()

	eng := engine.New()

	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux, eng)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("TCPDumper listening on http://localhost%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
