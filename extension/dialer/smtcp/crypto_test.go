package smtcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/aead/serpent"
	sm4onaes "github.com/emmansun/gmsm/sm4"
	"github.com/tjfoc/gmsm/sm4"
	"testing"
)

func BenchmarkAESGCM(b *testing.B) {
	key := make([]byte, 16)
	data := make([]byte, 16)
	nonce := make([]byte, 12)
	rand.Read(key)
	rand.Read(data)
	rand.Read(nonce)
	ciph, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(ciph)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gcm.Open(nil, nonce, data, nil)
	}
}

func BenchmarkSM4GCM(b *testing.B) {
	key := make([]byte, 16)
	data := make([]byte, 16)
	nonce := make([]byte, 12)
	rand.Read(key)
	rand.Read(data)
	rand.Read(nonce)
	ciph, _ := sm4.NewCipher(key)
	gcm, _ := cipher.NewGCM(ciph)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gcm.Open(nil, nonce, data, nil)
	}
}

func BenchmarkSM4onAESGCM(b *testing.B) {
	key := make([]byte, 16)
	data := make([]byte, 16)
	nonce := make([]byte, 12)
	rand.Read(key)
	rand.Read(data)
	rand.Read(nonce)
	ciph, _ := sm4onaes.NewCipher(key)
	gcm, _ := cipher.NewGCM(ciph)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gcm.Open(nil, nonce, data, nil)
	}
}

func BenchmarkSerpent(b *testing.B) {
	key := make([]byte, 16)
	data := make([]byte, 16)
	rand.Read(key)
	rand.Read(data)
	cipher, _ := serpent.NewCipher(key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Encrypt(data, data)
	}
}

func BenchmarkSerpentGCM(b *testing.B) {
	key := make([]byte, 16)
	data := make([]byte, 16)
	nonce := make([]byte, 12)
	rand.Read(key)
	rand.Read(data)
	rand.Read(nonce)
	ciph, _ := serpent.NewCipher(key)
	gcm, _ := cipher.NewGCM(ciph)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gcm.Open(nil, nonce, data, nil)
	}
}

func BenchmarkSM4(b *testing.B) {
	key := make([]byte, 16)
	data := make([]byte, 16)
	rand.Read(key)
	rand.Read(data)
	cipher, _ := sm4.NewCipher(key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Encrypt(data, data)
	}
}

func BenchmarkSM4onAES(b *testing.B) {
	key := make([]byte, 16)
	data := make([]byte, 16)
	rand.Read(key)
	rand.Read(data)
	cipher, _ := sm4onaes.NewCipher(key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Encrypt(data, data)
	}
}
