package attack

import (
	"encoding/json"
	"testing"
)

func TestWrapPayloadOpenAI(t *testing.T) {
	payload := messageParams{Messages: []message{
		{Role: "user", Content: "hello"},
	}}

	wrapped := wrapPayload(payload, "openai")
	data, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}

	var req openaiRequest
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatal(err)
	}
	if req.Model != "gpt-4" {
		t.Errorf("expected model gpt-4, got %s", req.Model)
	}
	if len(req.Messages) != 1 || req.Messages[0].Content != "hello" {
		t.Errorf("messages not preserved: %+v", req.Messages)
	}
}

func TestWrapPayloadAnthropic(t *testing.T) {
	payload := messageParams{Messages: []message{
		{Role: "user", Content: "hello"},
	}}

	wrapped := wrapPayload(payload, "anthropic")
	data, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}

	var req anthropicRequest
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatal(err)
	}
	if req.Model != "claude-sonnet-4-5-20250929" {
		t.Errorf("expected anthropic model, got %s", req.Model)
	}
	if req.MaxTokens != 1024 {
		t.Errorf("expected max_tokens 1024, got %d", req.MaxTokens)
	}
	if len(req.Messages) != 1 || req.Messages[0].Content != "hello" {
		t.Errorf("messages not preserved: %+v", req.Messages)
	}
}

func TestWrapPayloadRaw(t *testing.T) {
	payload := messageParams{Messages: []message{
		{Role: "user", Content: "hello"},
	}}

	wrapped := wrapPayload(payload, "raw")
	// Raw should return the payload unchanged
	mp, ok := wrapped.(messageParams)
	if !ok {
		t.Fatal("expected messageParams for raw format")
	}
	if len(mp.Messages) != 1 || mp.Messages[0].Content != "hello" {
		t.Errorf("raw payload should be unchanged: %+v", mp)
	}
}

func TestWrapPayloadNonMessageParams(t *testing.T) {
	payload := map[string]string{"key": "value"}
	wrapped := wrapPayload(payload, "openai")
	// Non-messageParams should pass through unchanged
	m, ok := wrapped.(map[string]string)
	if !ok {
		t.Fatal("expected map[string]string for non-messageParams")
	}
	if m["key"] != "value" {
		t.Errorf("payload should be unchanged: %+v", m)
	}
}

func TestExtractContentOpenAI(t *testing.T) {
	body := `{"choices":[{"message":{"content":"INJECTED_OK"}}]}`
	got := extractContent(body, "openai")
	if got != "INJECTED_OK" {
		t.Errorf("expected INJECTED_OK, got %q", got)
	}
}

func TestExtractContentOpenAIFallback(t *testing.T) {
	body := `not json at all`
	got := extractContent(body, "openai")
	if got != body {
		t.Errorf("expected fallback to raw body, got %q", got)
	}
}

func TestExtractContentOpenAIEmptyChoices(t *testing.T) {
	body := `{"choices":[]}`
	got := extractContent(body, "openai")
	if got != body {
		t.Errorf("expected fallback to raw body for empty choices, got %q", got)
	}
}

func TestExtractContentAnthropic(t *testing.T) {
	body := `{"content":[{"type":"text","text":"INJECTED_OK"}]}`
	got := extractContent(body, "anthropic")
	if got != "INJECTED_OK" {
		t.Errorf("expected INJECTED_OK, got %q", got)
	}
}

func TestExtractContentAnthropicFallback(t *testing.T) {
	body := `not json`
	got := extractContent(body, "anthropic")
	if got != body {
		t.Errorf("expected fallback to raw body, got %q", got)
	}
}

func TestExtractContentRaw(t *testing.T) {
	body := `{"response": "INJECTED_OK"}`
	got := extractContent(body, "raw")
	if got != body {
		t.Errorf("expected raw body returned as-is, got %q", got)
	}
}

func TestExtractContentEmpty(t *testing.T) {
	got := extractContent("", "openai")
	if got != "" {
		t.Errorf("expected empty string for empty input, got %q", got)
	}
}

func TestEndpointsForFormat(t *testing.T) {
	openaiEps := endpointsForFormat("openai")
	if openaiEps[0] != "/v1/chat/completions" {
		t.Errorf("openai first endpoint should be /v1/chat/completions, got %s", openaiEps[0])
	}

	anthropicEps := endpointsForFormat("anthropic")
	if anthropicEps[0] != "/v1/messages" {
		t.Errorf("anthropic first endpoint should be /v1/messages, got %s", anthropicEps[0])
	}

	rawEps := endpointsForFormat("raw")
	if rawEps[0] != "/" {
		t.Errorf("raw first endpoint should be /, got %s", rawEps[0])
	}
}
