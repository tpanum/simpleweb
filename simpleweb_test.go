package simpleweb_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tpanum/simpleweb"
)

func TestHTTPSRedirect(t *testing.T) {
	handler := simpleweb.RedirectHTTPSMiddleware("test.com")(http.NewServeMux())

	tt := []struct {
		name        string
		from        string
		to          string
		notRedirect bool
	}{
		{name: "domain", from: "http://example.com/foo", to: "https://test.com/foo"},
		{name: "ip", from: "http://192.168.1.1/foo", to: "https://test.com/foo"},
		{name: "should not redirect", from: "https://test.com/foo", notRedirect: true},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.from, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			resp := w.Result()
			if tc.notRedirect && resp.StatusCode == http.StatusFound {
				t.Fatalf("did not expect redirect")
				return
			}

			loc := resp.Header.Get("Location")
			if loc != tc.to {
				t.Fatalf("unexpected redirect (from: %s): %s", tc.from, loc)
			}
		})
	}

}
