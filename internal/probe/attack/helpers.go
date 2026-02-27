package attack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// openaiRequest wraps messages in an OpenAI-compatible chat completion request.
type openaiRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
}

// anthropicRequest wraps messages in an Anthropic messages API request.
type anthropicRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []message `json:"messages"`
}

// endpointsForFormat returns the list of endpoint paths to try for a given API format.
func endpointsForFormat(apiFormat string) []string {
	switch apiFormat {
	case "anthropic":
		return []string{"/v1/messages", "/messages", "/"}
	case "raw":
		return []string{"/", "/messages", "/mcp/messages", "/v1/messages", "/chat", "/api/chat", "/v1/chat/completions"}
	default: // "openai"
		return []string{"/v1/chat/completions", "/chat/completions", "/chat", "/"}
	}
}

// wrapPayload wraps a messageParams payload in the appropriate API envelope.
func wrapPayload(payload interface{}, apiFormat string) interface{} {
	mp, ok := payload.(messageParams)
	if !ok {
		return payload
	}
	switch apiFormat {
	case "openai":
		return openaiRequest{
			Model:    "gpt-4",
			Messages: mp.Messages,
		}
	case "anthropic":
		return anthropicRequest{
			Model:     "claude-sonnet-4-5-20250929",
			MaxTokens: 1024,
			Messages:  mp.Messages,
		}
	default: // "raw"
		return payload
	}
}

func postPayload(ctx context.Context, client *http.Client, baseURL string, payload interface{}, apiFormat string) (*http.Response, string, error) {
	if apiFormat == "" {
		apiFormat = "openai"
	}

	wrapped := wrapPayload(payload, apiFormat)
	endpoints := endpointsForFormat(apiFormat)

	data, err := json.Marshal(wrapped)
	if err != nil {
		return nil, "", err
	}

	var lastErr error
	var lastStatus int
	for _, ep := range endpoints {
		url := strings.TrimRight(baseURL, "/") + ep
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode < 400 {
			return resp, ep, nil
		}
		lastStatus = resp.StatusCode
		resp.Body.Close()
	}
	if lastErr != nil {
		return nil, "", fmt.Errorf("all endpoints failed: %w", lastErr)
	}
	return nil, "", fmt.Errorf("all endpoints returned HTTP errors (last status: %d)", lastStatus)
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

// extractContent pulls the AI response text out of an API response envelope.
func extractContent(body string, apiFormat string) string {
	if body == "" {
		return ""
	}
	switch apiFormat {
	case "openai":
		var resp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err == nil && len(resp.Choices) > 0 && resp.Choices[0].Message.Content != "" {
			return resp.Choices[0].Message.Content
		}
		return body
	case "anthropic":
		var resp struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err == nil && len(resp.Content) > 0 && resp.Content[0].Text != "" {
			return resp.Content[0].Text
		}
		return body
	default: // "raw"
		return body
	}
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
