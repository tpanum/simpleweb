package simpleweb_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tpanum/simpleweb"
)

func TestUser(t *testing.T) {
	pass := "secUasAsdlWas"
	u, err := simpleweb.NewUser("e@mail.com", pass)
	if err != nil {
		t.Fatalf("unexpected error when creating user: %s", err)
	}

	if u.ID.String() == "" {
		t.Fatalf("expected ID to be non-empty")
	}

	if u.HashedPassword == pass {
		t.Fatalf("expected password to be hased")
	}

	if !u.IsValidPassword(pass) {
		t.Fatalf("expected password to be valid")
	}

	if u.IsValidPassword("notequal") {
		t.Fatalf("expected password not to be valid")
	}
}

func TestUserStoreMemory(t *testing.T) {
	t.Run("Zero size", func(t *testing.T) {
		_, err := simpleweb.NewUserStoreMemory(0)
		if err == nil {
			t.Fatalf("expected error when creating store with size zero")
		}
	})

	t.Run("Normal", func(t *testing.T) {
		_, err := simpleweb.NewUserStoreMemory(5)
		if err != nil {
			t.Fatalf("expected no error when creating store with size five: %s", err)
		}
	})
}

func TestUserStoreMemoryAdd(t *testing.T) {
	knownUser, err := simpleweb.NewUser("some@email.com", "password")
	if err != nil {
		t.Fatalf("expected no error when creating known user")
	}

	tt := []struct {
		name  string
		users []*simpleweb.User
		err   string
	}{
		{name: "User without email", users: []*simpleweb.User{&simpleweb.User{ID: uuid.New()}}, err: "email cannot be empty"},
		{name: "User without ID", users: []*simpleweb.User{&simpleweb.User{Email: "email@email.com"}}, err: "id cannot be empty"},
		{name: "Existing user", users: []*simpleweb.User{knownUser}, err: "user already exists"},
		{name: "Too many users", users: []*simpleweb.User{&simpleweb.User{ID: uuid.New(), Email: "e@e.com"}, &simpleweb.User{ID: uuid.New(), Email: "e1@e.com"}}, err: "store is full"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			us, err := simpleweb.NewUserStoreMemory(2)
			if err != nil {
				t.Fatalf("expected no error when creating user store: %s", err)
			}

			if err := us.Add(knownUser); err != nil {
				t.Fatalf("expected no error adding known user: %s", err)
			}

			for _, u := range tc.users {
				uerr := us.Add(u)
				if uerr != nil {
					err = uerr
					break
				}
			}

			if err != nil {
				if tc.err == "" {
					t.Fatalf("unexpected error when adding user: %s", err)
				}

				if tc.err != err.Error() {
					t.Fatalf("received unexpected error (%s), when expected error: %s", err, tc.err)
				}

				return
			}

			if tc.err != "" {
				t.Fatalf("expected error (%s), but received none", tc.err)
			}

		})
	}
}

func TestUserStoreMemoryGetByID(t *testing.T) {
	knownUserOne, err := simpleweb.NewUser("some@email.com", "password")
	if err != nil {
		t.Fatalf("expected no error when creating known user")
	}

	knownUserTwo, err := simpleweb.NewUser("s@email.com", "password")
	if err != nil {
		t.Fatalf("expected no error when creating known user")
	}

	us, err := simpleweb.NewUserStoreMemory(2)
	if err != nil {
		t.Fatalf("expected no error when creating user store: %s", err)
	}

	for _, u := range []*simpleweb.User{knownUserOne, knownUserTwo} {
		if err := us.Add(u); err != nil {
			t.Fatalf("expected no error when adding user: %s", err)
		}
	}

	tt := []struct {
		name string
		uuid uuid.UUID
		find bool
	}{
		{name: "Unknown user", uuid: uuid.New()},
		{name: "Known user", uuid: knownUserOne.ID, find: true},
		{name: "Known user two", uuid: knownUserTwo.ID, find: true},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := us.GetByID(tc.uuid.String())
			if ok {
				if !tc.find {
					t.Fatalf("finds users, but expected none")
				}
				return
			}

			if tc.find {
				t.Fatalf("expected to find user, but found none")
			}

		})
	}
}

func TestUserStoreMemoryGetByEmail(t *testing.T) {
	e1 := "some@email.com"
	knownUserOne, err := simpleweb.NewUser(e1, "password")
	if err != nil {
		t.Fatalf("expected no error when creating known user")
	}

	e2 := "some2@email.com"
	knownUserTwo, err := simpleweb.NewUser(e2, "password")
	if err != nil {
		t.Fatalf("expected no error when creating known user")
	}

	us, err := simpleweb.NewUserStoreMemory(2)
	if err != nil {
		t.Fatalf("expected no error when creating user store: %s", err)
	}

	for _, u := range []*simpleweb.User{knownUserOne, knownUserTwo} {
		if err := us.Add(u); err != nil {
			t.Fatalf("expected no error when adding user: %s", err)
		}
	}

	tt := []struct {
		name  string
		email string
		find  bool
	}{
		{name: "Unknown user", email: "some_other@email.com"},
		{name: "Known user", email: e1, find: true},
		{name: "Known user two", email: e2, find: true},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := us.GetByEmail(tc.email)
			if ok {
				if !tc.find {
					t.Fatalf("finds users, but expected none")
				}
				return
			}

			if tc.find {
				t.Fatalf("expected to find user, but found none")
			}

		})
	}
}
