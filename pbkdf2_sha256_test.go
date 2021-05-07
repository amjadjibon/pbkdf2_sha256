package pbkdf2_sha256

import (
	"testing"
)

func TestVerifyPassword(t *testing.T) {
	tables := []struct {
		x string
		y string
		want bool
	}{
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
	}

	for _, table := range tables {
		res, err := VerifyPassword(table.x, table.y)
		if err != nil {
			t.Error(err)
		}
		if res != table.want {
			t.Errorf("pin: %s --> got: %v, want: %v.",table.x, res, table.want)
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	tables := []struct {
		x string
		y string
		want bool
	}{
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
		{"1234", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", true},
		{"1235", "pbkdf2_sha256$216000$sdTiwUYfPPbU$tE8/y4oXCaLFoesNT3ID8VsqH3Dm7fx8E3fDB1ejKpc=", false},
	}

	for _, table := range tables {
		res, err := VerifyPassword(table.x, table.y)
		if err != nil {
			b.Error(err)
		}
		if res != table.want {
			b.Errorf("pin: %s --> got: %v, want: %v.",table.x, res, table.want)
		}
	}
}
