package simpleweb

import (
	"net/http"
	"net/url"
)

const (
	HTTPS = "https"
)

func RedirectHTTPSMiddleware(host string) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, _ := url.Parse(r.RequestURI)
			if u.Host == host && u.Scheme == HTTPS {
				h.ServeHTTP(w, r)
				return
			}

			u.Host = host
			u.Scheme = HTTPS

			http.Redirect(w, r, u.String(), http.StatusFound)
		})
	}
}
