// Taken directly from code.google.com/p/go.crypto/bcrypt, except
// with minor changes in the alphabet constant
package gopass

import "encoding/base64"

// a string for mapping an int to the corresponding base 64 character.
const alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var bcEncoding = base64.NewEncoding(alphabet)

func base64Encode(src []byte) []byte {
    n := bcEncoding.EncodedLen(len(src))
    dst := make([]byte, n)
    bcEncoding.Encode(dst, src)
    for dst[n-1] == '=' {
        n--
    }
    return dst[:n]
}

func base64Decode(src []byte) ([]byte, error) {
    numOfEquals := 4 - (len(src) % 4)
    for i := 0; i < numOfEquals; i++ {
        src = append(src, '=')
    }

    dst := make([]byte, bcEncoding.DecodedLen(len(src)))
    n, err := bcEncoding.Decode(dst, src)
    if err != nil {
        return nil, err
    }
    return dst[:n], nil
}