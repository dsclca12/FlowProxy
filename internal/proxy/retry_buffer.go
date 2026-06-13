package proxy

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
)

type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

var bufferedResponsePool = sync.Pool{
	New: func() any {
		return &bufferedResponse{
			header: make(http.Header),
			status: http.StatusOK,
		}
	},
}

func newBufferedResponse() *bufferedResponse {
	br := bufferedResponsePool.Get().(*bufferedResponse)
	// Clear headers
	for k := range br.header {
		delete(br.header, k)
	}
	br.body.Reset()
	br.status = http.StatusOK
	return br
}

func putBufferedResponse(br *bufferedResponse) {
	if br == nil {
		return
	}
	bufferedResponsePool.Put(br)
}

func (w *bufferedResponse) Header() http.Header {
	return w.header
}

func (w *bufferedResponse) WriteHeader(statusCode int) {
	w.status = statusCode
}

func (w *bufferedResponse) Write(data []byte) (int, error) {
	return w.body.Write(data)
}

func (w *bufferedResponse) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *bufferedResponse) Bytes() []byte {
	return w.body.Bytes()
}

func copyHeader(dst http.Header, src http.Header) {
	for key := range dst {
		dst.Del(key)
	}
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func isUpgradeRequest(headers http.Header) bool {
	if headers == nil {
		return false
	}
	if strings.TrimSpace(headers.Get("Upgrade")) == "" {
		return false
	}
	connection := strings.ToLower(strings.TrimSpace(headers.Get("Connection")))
	return strings.Contains(connection, "upgrade")
}
