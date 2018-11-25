package simpleweb

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID             uuid.UUID
	Email          string
	HashedPassword string
	Info           interface{}
}

func NewUser(email, password string) (*User, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return nil, err
	}

	return &User{
		ID:             uuid.New(),
		Email:          email,
		HashedPassword: string(bytes),
	}, nil
}

func (u *User) IsValidPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.HashedPassword), []byte(password))
	return err == nil
}

var (
	EmptyEmailErr    = errors.New("email cannot be empty")
	EmptyIdErr       = errors.New("id cannot be empty")
	EmptyPasswordErr = errors.New("password cannot be empty")
	StoreFullErr     = errors.New("store is full")
	UserExistsErr    = errors.New("user already exists")
)

type UserStore interface {
	GetByID(string) (*User, bool)
	GetByEmail(string) (*User, bool)
	Add(*User) error
}

type storeMemory struct {
	m      sync.RWMutex
	max    int
	emails map[string]*User
	ids    map[uuid.UUID]*User
}

func NewUserStoreMemory(size int) (UserStore, error) {
	if size <= 0 {
		return nil, fmt.Errorf("size cannot less than one")
	}

	return &storeMemory{
		max:    size,
		emails: map[string]*User{},
		ids:    map[uuid.UUID]*User{},
	}, nil
}

func (sm *storeMemory) GetByID(id string) (*User, bool) {
	id = strings.TrimSpace(id)
	id = strings.ToLower(id)

	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, false
	}

	sm.m.RLock()
	defer sm.m.RUnlock()

	u, ok := sm.ids[uid]
	return u, ok
}

func (sm *storeMemory) GetByEmail(email string) (*User, bool) {
	email = strings.TrimSpace(email)
	email = strings.ToLower(email)

	sm.m.RLock()
	defer sm.m.RUnlock()

	u, ok := sm.emails[email]
	return u, ok
}

func (sm *storeMemory) Add(u *User) error {
	if u.Email == "" {
		return EmptyEmailErr
	}

	var empty uuid.UUID
	if u.ID == empty {
		return EmptyIdErr
	}

	sm.m.RLock()
	n := len(sm.emails)
	_, ok := sm.emails[u.Email]
	sm.m.RUnlock()

	if n >= sm.max {
		return StoreFullErr
	}

	if ok {
		return UserExistsErr
	}

	sm.m.Lock()
	sm.emails[u.Email] = u
	sm.ids[u.ID] = u
	sm.m.Unlock()

	return nil
}
