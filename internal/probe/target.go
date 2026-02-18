package probe

type Target struct {
	Path    string            `json:"path,omitempty"`
	URL     string            `json:"url,omitempty"`
	Options map[string]string `json:"-"`
}
