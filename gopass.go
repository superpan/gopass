// Porting Drupal 7 phpass algorithm into go
package gopass

// import bcrypt
import (
    //"code.google.com/p/go.crypto/bcrypt"
    "bytes"
    "crypto/rand"
    //"crypto/subtle"
    "crypto/sha512"
    //"encoding/base64"
    "errors"
    //"fmt"
    "io"
    //"math"
    //"strconv"
    //"strings"
)

// constants
const (
    DefaultHashCount    = 15
    MinHashCount        =  7
    MaxHashCount        = 30
    HashLength          = 55
    SaltLength          = 6
)

// hashed struct
type hashed struct {
    hash    []byte
    salt    []byte
    count   int // allowed range is MinCount to MaxCount
}

// errors
var InvalidCountError = errors.New("Invalid Count");
var InvalidSaltError = errors.New("Invalid Salt");

// hash password string
func Hash(password string, hashCount int) (hash string, err error) {
    var hashBytes []byte

    // convert both into bytes arrays
    hashBytes, err = HashBytes([]byte(password), hashCount)

    // convert hashBytes into string and return
    return string(hashBytes), err
}

func HashBytes(password []byte, hashCount int) ([]byte, error) {
    p, err := hashPassword(password, hashCount)
    if err != nil {
        return nil, err
    }
    return p.hash, nil
}

// internal function to hash password
func hashPassword(password []byte, hashCount int) (*hashed, error) {
    if hashCount < MinHashCount {
        hashCount = DefaultHashCount
    }
    p := new(hashed)
    p.count = hashCount

    newSalt, err := generateSalt(hashCount)
    if err != nil {
        return nil, err
    }
    p.salt = newSalt

    hash, err := encrypt(password, uint(p.count), p.salt)
    if err != nil {
        return nil, err
    }
    p.hash = hash
    return p, err 
}

// generate salt
func generateSalt(hashCount int) ([]byte, error) {
    // new buffer
    rs := bytes.NewBuffer(make([]byte, 0, 61))
    // append $S$
    rs.WriteString("$S$")
    // parse const
    constBytes := []byte(alphabet)
    rs.WriteByte(constBytes[hashCount])

    unencodedSalt := make([]byte, SaltLength)
    _, err := io.ReadFull(rand.Reader, unencodedSalt)
    if err != nil {
        return nil, err
    }
    encodedSalt := base64Encode(unencodedSalt)

    _, err = rs.Write(encodedSalt)
    if err != nil {
        return nil, err
    }

    return rs.Bytes(), nil
}

func validateSalt(salt []byte) bool {
    saltBuffer := bytes.NewBuffer(salt)
    // verify salt
    if !byteCheck(saltBuffer, '$') || !byteCheck(saltBuffer, 'S') || !byteCheck(saltBuffer, '$') {
        return false
    }

    return true
}

// password crypt
func encrypt(password []byte, count uint, salt []byte) ([]byte, error) {
    // make sure we only pull the first 12 characters
    salt = salt[0:12]
    if !validateSalt(salt) {
        return nil, InvalidSaltError
    }
    data := append(salt, password...)
    var i, rounds uint64
    rounds = 1 << count
    for i = 0; i < rounds; i++ {
        checksum := sha512.Sum512(data)
        // reinitialize data slice
        data = checksum[0:64]
    }

    return data[0:56], nil
}

// compare hash with password
func Compare(hash string, password string) bool {
    return false
}

// check if a byte is next up on the read buffer 
func byteCheck(r *bytes.Buffer, b byte) bool {
    got, err := r.ReadByte()
    if err != nil {
        return false
    }

    if got != b {
        r.UnreadByte()
        return false
    }

    return true
}
