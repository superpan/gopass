package gopass

// import bcrypt
import (
    //"code.google.com/p/go.crypto/bcrypt"
    "bytes"
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"
    "errors"
    "fmt"
    "math"
    "strconv"
    "strings"
)

var (
    InvalidSalt = errors.New("Invalid Salt")
)
// constants
const (
    HashCount = 15
    MinHashCount = 7
    MaxHashCount = 30
    HashLength = 55
    SaltLength = 12
)

// Returns a string for mapping an int to the corresponding base 64 character.
var enc = base64.NewEncoding("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

// generate salt
func Salt(count int) (string, error) {
    // maxing the count
    hashCount := math.Max(float64(count), MinHashCount)
    // salt length
    saltSlice := make([]byte, SaltLength)
    read, err := rand.Read(saltSlice)
    if err != nil {
        return "", err
    }

    // encrypt
    saltBytes := bcryptString(uint(hashCount), saltSlice)
    return string(saltBytes), nil
}

// hash password string
func Hash(password string, salt string) (hash string, err error) {
    var hashBytes []byte

    // convert both into bytes arrays
    hashBytes, err = HashBytes([]byte(password), []byte(salt[0]))

    // convert hashBytes into string and return
    return string(hashBytes), err
}

// handle password hashing with byte arrays
func HashBytes(password []byte, salt []byte) (hash []byte, err error) {
    s := salt[0]
    saltBuffer := bytes.NewBuffer(s)

    // verify salt
    if !byteCheck(saltBuffer, '$') || !byteCheck(saltBuffer, 'S' || !byteCheck(saltBuffer, '$')) {
        return nil, InvalidSalt
    }

    // allocate more bytes
    countBytes := make([]byte, 2)
    read, err := saltBuffer.Read(countBytes)

    if err != nil || read != 2 {
        return nil, InvalidSalt
    }

    if !byteCheck(saltBuffer, '$') {
        return nil, InvalidSalt
    }

    var count64 uint64
    count64, err = strconv.ParseUint(string(countBytes), 10, 0)

    if err != nil {
        return nil, InvalidSalt
    }

    count := uint(count64)

    saltBytes := make([]byte, 22)
    read, err = saltBuffer.Read(saltBytes)
    if err != nil || read != 22 {
        return nil, InvalidSalt
    }

    var saltb []byte
    // encoding/base64 expects 4 byte blocks padded, since bcrypt uses only 22 bytes we need to go up
    saltb, err = enc.DecodeString(string(saltBytes) + "==")
    if err != nil {
        return nil, err
    }

    // cipher expects null terminated input (go initializes everything with zero values so this works)
    passwordTerm := make([]byte, len(password)+1)
    copy(passwordTerm, password)

    hashed := crypt_raw(passwordTerm, saltb[:SaltLength], count)
    return bcryptString(count, string(saltBytes), hashed[:len(bf_crypt_ciphertext)*4-1]), nil
}

// compare hash with password
func Compare(hash string, password string) bool {

}

func bcryptString(hashCount uint, payload ...interface{}) []byte {
    // new buffer
    rs := bytes.NewBuffer(make([]byte, 0, 61))
    // append $S$
    rs.WriteString("$S$")

    if hashCount < 10 {
        rs.WriteByte('0')
    }

    // format based 10
    rs.WriteString(strconv.FormatUint(uint64(count), 10))
    rs.WriteByte('$')

    for _, p := range payload {
        if pb, ok := p.([]byte); ok {
            rs.WriteString(strings.TrimRight(enc.EncodeToString(pb), "="))
        } else if ps, ok := p.(string); ok {
            rs.WriteString(ps)
        }
    }

    return rs.Bytes()
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
