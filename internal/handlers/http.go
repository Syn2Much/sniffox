package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"sniffox/internal/engine"
	"sniffox/web"
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

	// PCAP export
	mux.HandleFunc("/api/export", handleExport(eng))

	// Session management
	mux.HandleFunc("/api/sessions", handleSessions(eng))
	mux.HandleFunc("/api/sessions/save", handleSessionSave(eng))
	mux.HandleFunc("/api/sessions/load", handleSessionLoad(eng))
	mux.HandleFunc("/api/sessions/delete", handleSessionDelete(eng))
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
		tmpFile, err := os.CreateTemp(tmpDir, "sniffox-*.pcap")
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

func handleExport(eng *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sniffox-%s.pcap\"", time.Now().Format("20060102-150405")))
		if err := eng.ExportPcap(w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

const sessionsDir = "sessions"

type sessionMeta struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Timestamp string `json:"timestamp"`
	Packets   int    `json:"packets"`
	Size      int64  `json:"size"`
}

func ensureSessionsDir() error {
	return os.MkdirAll(sessionsDir, 0o755)
}

func handleSessions(eng *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		if err := ensureSessionsDir(); err != nil {
			http.Error(w, "sessions dir error", http.StatusInternalServerError)
			return
		}
		entries, err := os.ReadDir(sessionsDir)
		if err != nil {
			json.NewEncoder(w).Encode([]sessionMeta{})
			return
		}
		var sessions []sessionMeta
		for _, e := range entries {
			if filepath.Ext(e.Name()) != ".json" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(sessionsDir, e.Name()))
			if err != nil {
				continue
			}
			var meta sessionMeta
			if json.Unmarshal(data, &meta) == nil {
				sessions = append(sessions, meta)
			}
		}
		if sessions == nil {
			sessions = []sessionMeta{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sessions)
	}
}

func handleSessionSave(eng *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if err := ensureSessionsDir(); err != nil {
			http.Error(w, "sessions dir error", http.StatusInternalServerError)
			return
		}

		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			req.Name = "Capture"
		}

		count := eng.PacketCount()
		if count == 0 {
			http.Error(w, "No packets to save", http.StatusBadRequest)
			return
		}

		id := time.Now().Format("20060102-150405")
		pcapPath := filepath.Join(sessionsDir, id+".pcap")
		f, err := os.Create(pcapPath)
		if err != nil {
			http.Error(w, "Failed to create session file", http.StatusInternalServerError)
			return
		}
		if err := eng.ExportPcap(f); err != nil {
			f.Close()
			os.Remove(pcapPath)
			http.Error(w, "Failed to write pcap: "+err.Error(), http.StatusInternalServerError)
			return
		}
		f.Close()

		fi, _ := os.Stat(pcapPath)
		var size int64
		if fi != nil {
			size = fi.Size()
		}

		meta := sessionMeta{
			ID:        id,
			Name:      req.Name,
			Timestamp: time.Now().Format(time.RFC3339),
			Packets:   count,
			Size:      size,
		}
		metaData, _ := json.Marshal(meta)
		os.WriteFile(filepath.Join(sessionsDir, id+".json"), metaData, 0o644)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}
}

func handleSessionLoad(eng *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
			http.Error(w, "Missing session ID", http.StatusBadRequest)
			return
		}
		// Sanitize ID to prevent path traversal
		base := filepath.Base(req.ID)
		pcapPath := filepath.Join(sessionsDir, base+".pcap")
		if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}

		eng.StopCapture()
		if err := eng.LoadPcapFile(pcapPath); err != nil {
			http.Error(w, "Failed to load session: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}
}

func handleSessionDelete(eng *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
			http.Error(w, "Missing session ID", http.StatusBadRequest)
			return
		}
		base := filepath.Base(req.ID)
		os.Remove(filepath.Join(sessionsDir, base+".pcap"))
		os.Remove(filepath.Join(sessionsDir, base+".json"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}
}
