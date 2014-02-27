package gopass

// import bcrypt
import (
    "code.google.com/p/go.crypto/bcrypt"
    "encoding/base64"
    "math"
)
// constants
const (
    HashCount = 15
    MinHashCount = 7
    MaxHashCount = 30
    HashLength = 55
)

// Returns a string for mapping an int to the corresponding base 64 character.
func passwordItoa64() string {
    return './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
}

func passwordGenerateSalt(countLog2 float64) string {
    output := '$S$'
    countLog2 = math.Max(countLog2, MinHashCount)
}

// Hash a password using a secure stretched hash
func passwordCrypt(password []byte) ([]byte, error) {
    defer clear(password)
}

func clear(b []byte) {
    for i := 0; i< len(b); i++ {
        b[i] = 0;
    }
}