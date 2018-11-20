package simpleweb

import (
	"net/http"
	"net/url"
)

func RedirectHTTPSMiddleware(host string) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, _ := url.Parse(r.RequestURI)
			u.Host = host
			u.Scheme = "https"

			http.Redirect(w, r, u.String(), http.StatusFound)
		})
	}
}
