package simpleweb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

const (
	HTTPS               = "https"
	JWT_KEY_ID          = "i"
	JWT_KEY_VALID_UNTIL = "v"
)

var (
	EmptyCKeyErr     = errors.New("cookie key cannot be empty")
	EmptySKeyErr     = errors.New("signing key cannot be empty")
	EmptyDurationErr = errors.New("duration cannot be empty")
)

type CtxUser struct{}

type ResultHandler func(err error, w http.ResponseWriter, r *http.Request)

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

type AuthorizerOpt func(*authorizer) error

func WithCookieKey(ckey string) AuthorizerOpt {
	return func(a *authorizer) error {
		if ckey == "" {
			return EmptyCKeyErr
		}

		a.ckey = ckey

		return nil
	}
}

func WithSigningKey(skey string) AuthorizerOpt {
	return func(a *authorizer) error {
		if skey == "" {
			return EmptySKeyErr
		}

		a.skey = skey

		return nil
	}
}

func WithExpire(d time.Duration) AuthorizerOpt {
	return func(a *authorizer) error {
		var empty time.Duration
		if d == empty {
			return EmptyDurationErr
		}

		a.expireAfter = d

		return nil
	}
}

func WithResultHandler(rh ResultHandler) AuthorizerOpt {
	return func(a *authorizer) error {
		a.resultHandler = rh

		return nil
	}
}

type authorizer struct {
	us            UserStore
	ckey          string
	skey          string
	resultHandler ResultHandler
	expireAfter   time.Duration
}

func NewAuthorizer(us UserStore, opts ...AuthorizerOpt) *authorizer {
	a := &authorizer{
		us:          us,
		ckey:        "session",
		skey:        uuid.New().String(),
		expireAfter: 7 * 24 * time.Hour,
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (a *authorizer) userFromRequest(r *http.Request) (*User, error) {
	cookie, err := r.Cookie(a.ckey)
	if err != nil {
		return nil, err
	}

	jwtToken, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(a.skey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok || !jwtToken.Valid {
		return nil, fmt.Errorf("unable to read claims from jwt")
	}

	id, ok := claims[JWT_KEY_ID].(string)
	if !ok {
		return nil, fmt.Errorf("unable to find id in jwt")
	}

	u, ok := a.us.GetByID(id)
	if !ok {
		return nil, fmt.Errorf("unable to find user with id from jwt")
	}

	return u, nil
}

func (a *authorizer) AuthorizeCtxMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := a.userFromRequest(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), CtxUser{}, u))
		next.ServeHTTP(w, r)
	})
}

var (
	InvalidLoginErr = errors.New("email or password is incorrect")
)

func (a *authorizer) LoginUser(email, password string) (string, error) {
	validTo := time.Now().Add(a.expireAfter)
	u, ok := a.us.GetByEmail(email)
	if !ok {
		return "", InvalidLoginErr
	}

	if ok := u.IsValidPassword(password); !ok {
		return "", InvalidLoginErr
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		JWT_KEY_ID:          u.ID,
		JWT_KEY_VALID_UNTIL: validTo.Unix(),
	})

	tokenString, err := token.SignedString([]byte(a.skey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (a *authorizer) WriteTokenToResponse(token string, w http.ResponseWriter) {
	validTo := time.Now().Add(a.expireAfter)
	cookie := http.Cookie{Name: a.ckey, Value: token, Expires: validTo}
	http.SetCookie(w, &cookie)
}

func (a *authorizer) LoginHandler() http.Handler {
	requestToToken := func(r *http.Request) (string, error) {
		email := r.FormValue("email")
		if email == "" {
			return "", EmptyEmailErr
		}

		password := r.FormValue("password")
		if password == "" {
			return "", EmptyPasswordErr
		}

		return a.LoginUser(email, password)
	}

	if a.resultHandler != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := requestToToken(r)
			if err != nil {
				a.resultHandler(err, w, r)
			}

			a.WriteTokenToResponse(token, w)
			a.resultHandler(nil, w, r)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := requestToToken(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
		}

		a.WriteTokenToResponse(token, w)
		http.Redirect(w, r, "/", http.StatusFound)
	})
}
