package attack

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

func newClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

type mcpRequest struct {
	Method string      `json:"method"`
	Params interface{} `json:"params,omitempty"`
}

type messageParams struct {
	Messages []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type toolCallParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments"`
}

func postPayload(ctx context.Context, client *http.Client, baseURL string, payload interface{}) (*http.Response, string, error) {
	endpoints := []string{"/", "/messages", "/mcp/messages", "/v1/messages", "/chat", "/api/chat", "/v1/chat/completions"}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}

	for _, ep := range endpoints {
		url := strings.TrimRight(baseURL, "/") + ep
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode < 400 {
			return resp, ep, nil
		}
		resp.Body.Close()
	}
	return nil, "", nil
}

func readResponseBody(resp *http.Response, maxBytes int64) string {
	if resp == nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return ""
	}
	return string(body)
}

func containsAny(s string, indicators []string) bool {
	lower := strings.ToLower(s)
	for _, ind := range indicators {
		if strings.Contains(lower, strings.ToLower(ind)) {
			return true
		}
	}
	return false
}
