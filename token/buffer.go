package token

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// tokenPool reuses Token structs to avoid repeated allocations inside generators.
var tokenPool = sync.Pool{
	New: func() any {
		return &Token{
			Header:       make(map[string]string, 4),
			Claims:       make(map[string]any, 8),
			BinaryClaims: make(map[string][]byte, 4),
			Footer:       make(map[string]string, 4),
		}
	},
}

func acquireToken() *Token {
	t := tokenPool.Get().(*Token)
	resetToken(t)
	return t
}

func releaseToken(t *Token) {
	if t == nil {
		return
	}
	resetToken(t)
	tokenPool.Put(t)
}

func resetToken(t *Token) {
	for k := range t.Header {
		delete(t.Header, k)
	}
	for k := range t.Claims {
		delete(t.Claims, k)
	}
	for k := range t.BinaryClaims {
		delete(t.BinaryClaims, k)
	}
	for k := range t.Footer {
		delete(t.Footer, k)
	}
	if len(t.RawClaim) > 0 {
		clear(t.RawClaim)
		t.RawClaim = t.RawClaim[:0]
	}
	t.RawClaim = nil
	t.ID = ""
	t.IssuedAt = time.Time{}
	t.NotBefore = time.Time{}
	t.ExpiresAt = time.Time{}
	t.Blacklisted = false
}

//  SERIALIZATION / DESERIALIZATION (MANUAL, ZERO-ALLOC BEYOND POOL)

// bytePool holds a reusable byte slice to minimize allocations.
var bytePool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

// appendString appends length-prefixed string to buf: [uint16(len)] + bytes.
func appendString(buf *[]byte, s string) {
	if buf == nil {
		return
	}
	b := *buf
	n := len(s)
	if n > 65535 {
		panic("string too long for uint16 length prefix")
	}
	b = append(b, byte(n>>8), byte(n))
	b = append(b, s...)
	*buf = b
}

// readString reads a length-prefixed string from data starting at idx.
func readString(data []byte, idx *int) (string, error) {
	if idx == nil {
		return "", ErrInvalidToken
	}
	if *idx+2 > len(data) {
		return "", ErrInvalidToken
	}
	length := int(data[*idx])<<8 | int(data[*idx+1])
	*idx += 2
	if length < 0 || *idx+length > len(data) {
		return "", ErrInvalidToken
	}
	s := string(data[*idx : *idx+length])
	*idx += length
	return s, nil
}

// Add a pool for JSON marshaling buffers
var jsonBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 256)
		return &buf
	},
}

// Add pools for reusing key slices.
var headerKeysPool = sync.Pool{
	New: func() any { return make([]string, 0, 8) },
}

var claimKeysPool = sync.Pool{
	New: func() any { return make([]string, 0, 8) },
}

var footerKeysPool = sync.Pool{
	New: func() any { return make([]string, 0, 8) },
}

// Add a pool for reusing nonce slices.
var noncePool = sync.Pool{
	New: func() any {
		nonce := make([]byte, chacha20poly1305.NonceSizeX)
		return &nonce
	},
}

type serializedBuffer struct {
	ptr *[]byte
	buf []byte
}

func (s *serializedBuffer) Bytes() []byte { return s.buf }

// Detach hands ownership of the underlying slice to the caller without returning it to the pool.
func (s *serializedBuffer) Detach() []byte {
	buf := s.buf
	s.ptr = nil
	return buf
}

// Release zeros sensitive material and returns the buffer to the pool.
func (s *serializedBuffer) Release() {
	if s == nil || s.ptr == nil {
		return
	}
	buf := s.buf
	for i := range buf {
		buf[i] = 0
	}
	*s.ptr = buf[:0]
	bytePool.Put(s.ptr)
	s.ptr = nil
}
// appendJSON efficiently marshals value to buf without allocations for common types
func appendJSON(buf *[]byte, v any) error {
	if buf == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		*buf = append(*buf, '"')
		*buf = append(*buf, val...)
		*buf = append(*buf, '"')
	case int:
		*buf = appendInt(*buf, int64(val))
	case int64:
		*buf = appendInt(*buf, val)
	case float64:
		*buf = appendFloat(*buf, val)
	case bool:
		if val {
			*buf = append(*buf, "true"...)
		} else {
			*buf = append(*buf, "false"...)
		}
	case nil:
		*buf = append(*buf, "null"...)
	default:
		// Fallback to json.Marshal for complex types
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		*buf = append(*buf, data...)
	}
	return nil
}

func appendInt(buf []byte, val int64) []byte {
	if val == 0 {
		return append(buf, '0')
	}
	if val < 0 {
		buf = append(buf, '-')
		val = -val
	}
	start := len(buf)
	for val > 0 {
		buf = append(buf, byte('0'+val%10))
		val /= 10
	}
	// Reverse digits
	for i, j := start, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return buf
}

func appendFloat(buf []byte, val float64) []byte {
	// Simple float formatting - for production use strconv.FormatFloat
	return append(buf, []byte(fmt.Sprintf("%g", val))...)
}
