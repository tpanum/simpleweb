package simpleweb

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	HTTPS      = "https"
	JWT_KEY_ID = "i"
)

type ctxUser struct{}

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

func Authorize(us UserStore, ckey, skey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(ckey)
			if err != nil {
				return
			}

			jwtToken, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				return []byte(skey), nil
			})
			if err != nil {
				return
			}

			claims, ok := jwtToken.Claims.(jwt.MapClaims)
			if !ok || !jwtToken.Valid {
				return
			}

			id, ok := claims[JWT_KEY_ID].(string)
			if !ok {
				return
			}

			u, ok := us.GetByID(id)
			if !ok {
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), ctxUser{}, u))

			next.ServeHTTP(w, r)
		})
	}
}
