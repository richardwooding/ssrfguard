package ssrfguard_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/richardwooding/ssrfguard"
)

// Example shows a guarded HTTP client refusing to connect to an internal
// address. The test server listens on loopback, so the dial is blocked.
func Example() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := ssrfguard.New().Client().Get(srv.URL)
	fmt.Println(errors.Is(err, ssrfguard.ErrBlockedAddress))
	// Output: true
}

// ExampleGuard_ValidateURL shows up-front URL validation: the cloud metadata
// endpoint is blocked while a public address is allowed.
func ExampleGuard_ValidateURL() {
	g := ssrfguard.New()
	fmt.Println(g.ValidateURL("http://169.254.169.254/latest/meta-data/") != nil)
	fmt.Println(g.ValidateURL("https://8.8.8.8") == nil)
	// Output:
	// true
	// true
}
