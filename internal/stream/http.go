package stream

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// HTTPTransaction holds extracted HTTP request/response data.
type HTTPTransaction struct {
	Method      string            `json:"method,omitempty"`
	URL         string            `json:"url,omitempty"`
	StatusCode  int               `json:"statusCode,omitempty"`
	StatusText  string            `json:"statusText,omitempty"`
	ReqHeaders  map[string]string `json:"reqHeaders,omitempty"`
	RespHeaders map[string]string `json:"respHeaders,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
	BodyPreview string            `json:"bodyPreview,omitempty"`
}

// tryParseHTTP attempts to parse HTTP request from clientData and response from serverData.
// Returns nil if the data doesn't look like HTTP.
func tryParseHTTP(clientData, serverData []byte) (*HTTPTransaction, error) {
	if len(clientData) < 4 {
		return nil, fmt.Errorf("insufficient data")
	}

	// Quick check: does it start with an HTTP method?
	start := string(clientData[:4])
	if start != "GET " && start != "POST" && start != "PUT " && start != "DELE" &&
		start != "HEAD" && start != "PATC" && start != "OPTI" {
		return nil, fmt.Errorf("not HTTP")
	}

	tx := &HTTPTransaction{
		ReqHeaders:  make(map[string]string),
		RespHeaders: make(map[string]string),
	}

	// Parse request
	reader := bufio.NewReader(bytes.NewReader(clientData))
	req, err := http.ReadRequest(reader)
	if err == nil {
		tx.Method = req.Method
		tx.URL = req.URL.String()
		for k, v := range req.Header {
			tx.ReqHeaders[k] = strings.Join(v, ", ")
		}
		tx.ContentType = req.Header.Get("Content-Type")
		req.Body.Close()
	}

	// Parse response
	if len(serverData) >= 12 {
		respReader := bufio.NewReader(bytes.NewReader(serverData))
		resp, err := http.ReadResponse(respReader, nil)
		if err == nil {
			tx.StatusCode = resp.StatusCode
			tx.StatusText = resp.Status
			for k, v := range resp.Header {
				tx.RespHeaders[k] = strings.Join(v, ", ")
			}
			if tx.ContentType == "" {
				tx.ContentType = resp.Header.Get("Content-Type")
			}

			// Read a small body preview
			bodyBuf := make([]byte, 512)
			n, _ := io.ReadAtLeast(resp.Body, bodyBuf, 1)
			if n > 0 {
				preview := string(bodyBuf[:n])
				// Only keep printable ASCII
				var sb strings.Builder
				for _, c := range preview {
					if c >= 32 && c < 127 || c == '\n' || c == '\r' || c == '\t' {
						sb.WriteRune(c)
					} else {
						sb.WriteByte('.')
					}
				}
				tx.BodyPreview = sb.String()
			}
			resp.Body.Close()
		}
	}

	if tx.Method == "" && tx.StatusCode == 0 {
		return nil, fmt.Errorf("could not parse HTTP")
	}

	return tx, nil
}
