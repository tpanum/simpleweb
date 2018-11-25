package simpleweb_test

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestAuthorizerLoginHandler(t *testing.T) {
	ts, err := simpleweb.NewUserStoreMemory(10)
	if err != nil {
		t.Fatalf("unexpected error when creating team store: %s", err)
	}

	t1, _ := simpleweb.NewUser("a@a.com", "123456")
	t2, _ := simpleweb.NewUser("b@b.com", "654321")

	ts.Add(t1)
	ts.Add(t2)

	a := simpleweb.NewAuthorizer(ts, simpleweb.WithSigningKey("wLwknad)12nv/dxtAw"))

	tt := []struct {
		name   string
		fields map[string]string
		err    string
	}{
		{name: "Normal team #1", fields: map[string]string{"email": "a@a.com", "password": "123456"}},
		{name: "Incorrect team #1", fields: map[string]string{"email": "a@a.com", "password": "123452"}, err: "email or password is incorrect"},
		{name: "Normal team #2", fields: map[string]string{"email": "b@b.com", "password": "654321"}},
		{name: "Empty email", fields: map[string]string{"password": "654321"}, err: "email cannot be empty"},
		{name: "Empty password", fields: map[string]string{"email": "a@a.com"}, err: "password cannot be empty"},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			for k, v := range tc.fields {
				form.Set(k, v)
			}

			req := httptest.NewRequest("POST", "http://test.com/login", strings.NewReader(form.Encode()))
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			w := httptest.NewRecorder()
			a.LoginHandler().ServeHTTP(w, req)

			resp := w.Result()
			okLogin := resp.StatusCode == http.StatusFound
			content, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("expected no error when reading body: %s", err)
			}
			defer resp.Body.Close()
			contentStr := string(content)

			if tc.err != "" {
				if contentStr != tc.err {
					t.Fatalf("expected error (%s), but received: %s", tc.err, contentStr)
				}

				return
			}

			if contentStr != "" {
				t.Fatalf("expected empty body, but got body: %s", contentStr)
			}

			if !okLogin {
				t.Fatalf("expected to be able to login, but got status code: %d", resp.StatusCode)
			}
		})
	}

}
