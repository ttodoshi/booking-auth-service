package password

import (
	"github.com/brianvoe/gofakeit/v6"
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := gofakeit.Password(true, true, true, true, false, 8)
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Errorf("HashPassword returned an error: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		t.Errorf("Hashed password is not valid: %v", err)
	}
}

func TestVerifyPassword(t *testing.T) {
	password := gofakeit.Password(true, true, true, true, false, 8)
	hashedPassword, _ := HashPassword(password)

	err := VerifyPassword(hashedPassword, password)
	if err != nil {
		t.Errorf("VerifyPassword returned an error: %v", err)
	}
}
