package main

import (
   "crypto/sha256"
   "fmt"
)

func main() {
   guid := [16]byte{1}
   derived_key, err := DerivePlayReadyContentKey(playReadyTestKeySeed, guid[:])
   if err != nil {
      panic(err)
   }
   fmt.Printf("%x\n", derived_key)
}

// playReadyTestKeySeed is the 30-byte PlayReady Test Key Seed (Base64 decoded)
// This is for the Microsoft PlayReady test server (testweb.playready.microsoft.com)
var playReadyTestKeySeed = []byte{
   0x5D, 0x50, 0x68, 0xBE, 0xC9, 0xB3, 0x84, 0xFF,
   0x60, 0x44, 0x86, 0x71, 0x59, 0xF1, 0x6D, 0x6B,
   0x75, 0x55, 0x44, 0xFC, 0xD5, 0x11, 0x69, 0x89,
   0xB1, 0xAC, 0xC4, 0x27, 0x8E, 0x88,
}

func DerivePlayReadyContentKey(keySeed []byte, keyId []byte) ([]byte, error) {
   if len(keySeed) != 30 {
      return nil, fmt.Errorf("keySeed must be 30 bytes, got %d", len(keySeed))
   }
   if len(keyId) != 16 {
      return nil, fmt.Errorf("keyId must be 16 bytes, got %d", len(keyId))
   }
   // 1. Calculate digest_A = SHA256 ( keySeed + keyId )
   hA := sha256.New()
   hA.Write(keySeed)
   hA.Write(keyId)
   digestA := hA.Sum(nil) // 32 bytes
   // 2. Calculate digest_B = SHA256 ( keySeed + keyId + keySeed )
   hB := sha256.New()
   hB.Write(keySeed)
   hB.Write(keyId)
   hB.Write(keySeed)
   digestB := hB.Sum(nil) // 32 bytes
   // 3. Calculate digest_C = SHA256 ( keySeed + keyId + keySeed + keyId )
   hC := sha256.New()
   hC.Write(keySeed)
   hC.Write(keyId)
   hC.Write(keySeed)
   hC.Write(keyId)
   digestC := hC.Sum(nil) // 32 bytes
   // 4. Derive the 16-byte Content Key
   contentKey := make([]byte, 16)
   for i := 0; i < 16; i++ {
      contentKey[i] = digestA[i] ^ digestA[i+16] ^
         digestB[i] ^ digestB[i+16] ^
         digestC[i] ^ digestC[i+16]
   }
   return contentKey, nil
}
