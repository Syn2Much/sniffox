package handlers

import (
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	"dumptcp/internal/engine"
	"dumptcp/web"
)

const maxUploadSize = 100 << 20 // 100 MB

// RegisterRoutes sets up all HTTP routes on the given mux.
func RegisterRoutes(mux *http.ServeMux, eng *engine.Engine) {
	// Serve embedded static files
	staticFS, _ := fs.Sub(web.StaticFiles, "static")
	fileServer := http.FileServer(http.FS(staticFS))
	mux.Handle("/", fileServer)

	// WebSocket endpoint
	mux.HandleFunc("/ws", HandleWebSocket(eng))

	// PCAP file upload
	mux.HandleFunc("/api/upload", handleUpload(eng))
}

func handleUpload(eng *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
		if err := r.ParseMultipartForm(maxUploadSize); err != nil {
			http.Error(w, "File too large (max 100MB)", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Missing file", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Write to temp file (gopacket/pcap needs a file path)
		tmpDir := os.TempDir()
		tmpFile, err := os.CreateTemp(tmpDir, "tcpdumper-*.pcap")
		if err != nil {
			http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
			return
		}
		tmpPath := tmpFile.Name()
		defer os.Remove(tmpPath)

		if _, err := io.Copy(tmpFile, file); err != nil {
			tmpFile.Close()
			http.Error(w, "Failed to save file", http.StatusInternalServerError)
			return
		}
		tmpFile.Close()

		_ = header // filename available via header.Filename if needed
		_ = filepath.Base(tmpPath)

		// Stop any active capture before loading file
		eng.StopCapture()

		if err := eng.LoadPcapFile(tmpPath); err != nil {
			http.Error(w, "Failed to read pcap: "+err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}
}
