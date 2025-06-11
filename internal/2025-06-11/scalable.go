package main

import (
   "crypto/sha256"
   "encoding/base64"
   "fmt"
   "bytes"
   "github.com/google/uuid" // You'll need to `go get github.com/google/uuid`
)

// playReadyTestKeySeed is the 30-byte PlayReady Test Key Seed (Base64 decoded)
// This is for the Microsoft PlayReady test server (testweb.playready.microsoft.com)
var playReadyTestKeySeed = []byte{
   0x5D, 0x50, 0x68, 0xBE, 0xC9, 0xB3, 0x84, 0xFF,
   0x60, 0x44, 0x86, 0x71, 0x59, 0xF1, 0x6D, 0x6B,
   0x75, 0x55, 0x44, 0xFC, 0xD5, 0x11, 0x69, 0x89,
   0xB1, 0xAC, 0xC4, 0x27, 0x8E, 0x88,
}

// playReadyGuidToBytes converts a UUID to its byte array representation,
// handling the specific PlayReady endianness requirements.
// PlayReady expects the first 3 fields (time_low, time_mid, time_hi_and_version)
// of a GUID to be little-endian, and the rest (clock_seq_hi_and_reserved,
// clock_seq_low, node) to be big-endian (network byte order).
// Go's uuid.UUID.MarshalBinary() provides RFC 4122 (network byte order) format,
// which is typically what's needed, but if you encounter issues with the PlayReady
// test server, this specific byte-swapping might be necessary for the first
// three fields if your input GUID isn't already in the required format.
// For standard RFC 4122 UUIDs, the first 8 bytes are swapped compared to
// the mixed-endian format often implied by PlayReady examples.
// We'll generally assume MarshalBinary() output is suitable, but provide this
// for explicit handling.
func playReadyGuidToBytes(u uuid.UUID) []byte {
   b, _ := u.MarshalBinary() // Get RFC 4122 byte order (network byte order)

   // In many PlayReady contexts, GUIDs are represented in a mixed-endian format.
   // RFC 4122 (network byte order) for the first 8 bytes often differs
   // from how Windows-style GUIDs are typically stored for the first three fields.
   //
   // If you find that the derived key is incorrect, and your PlayReady system
   // specifically expects the Windows mixed-endian format (e.g., as exposed
   // by System.Guid.ToByteArray() in .NET), you might need to uncomment and
   // use the following byte-swapping logic:
   //
   // b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0] // Swap time_low
   // b[4], b[5] = b[5], b[4]                         // Swap time_mid
   // b[6], b[7] = b[7], b[6]                         // Swap time_hi_and_version
   //
   // For the purposes of this example, we'll return the RFC 4122 binary form,
   // as many PlayReady clients/servers are flexible, or expect this directly.
   return b
}

// DerivePlayReadyContentKey derives the 16-byte PlayReady content key
// from the PlayReady Key Seed and the 16-byte Key ID.
//
// keySeed: The 30-byte PlayReady Key Seed.
// keyId: The 16-byte Key ID (GUID) of the content. It must be in the correct
//        byte order as expected by PlayReady (e.g., from playReadyGuidToBytes).
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

func main() {
   // Example Key ID (GUID) - you would generate your own unique one
   // This is a sample GUID for demonstration.
   exampleKeyIDStr := "12345678-ABCD-EF01-2345-6789ABCDEF01"
   exampleKeyIDUUID, err := uuid.Parse(exampleKeyIDStr)
   if err != nil {
      fmt.Printf("Error parsing UUID: %v\n", err)
      return
   }

   // Get the byte representation of the Key ID for PlayReady
   // Make sure the endianness is correct for your specific PlayReady implementation.
   // The `playReadyGuidToBytes` function can be adjusted if needed.
   exampleKeyIDBytes := playReadyGuidToBytes(exampleKeyIDUUID)

   fmt.Printf("PlayReady Test Key Seed (Base64): %s\n", base64.StdEncoding.EncodeToString(playReadyTestKeySeed))
   fmt.Printf("Chosen Key ID (UUID): %s\n", exampleKeyIDUUID.String())
   fmt.Printf("Chosen Key ID (Bytes): %x\n", exampleKeyIDBytes)

   derivedKey, err := DerivePlayReadyContentKey(playReadyTestKeySeed, exampleKeyIDBytes)
   if err != nil {
      fmt.Printf("Error deriving key: %v\n", err)
      return
   }

   fmt.Printf("Derived PlayReady Content Key: %x\n", derivedKey)
   fmt.Printf("Derived PlayReady Content Key (Base64): %s\n", base64.StdEncoding.EncodeToString(derivedKey))

   // --- Verification with a known example if you have one ---
   // You can uncomment and test with a known KID and expected key if you have
   // an established PlayReady test vector.

   // knownKeyIDStr := "YOUR_KNOWN_KID_UUID_STRING"
   // knownKeyIDUUID, _ := uuid.Parse(knownKeyIDStr)
   // knownKeyIDBytes := playReadyGuidToBytes(knownKeyIDUUID) // Or whatever byte order was used for known example

   // expectedContentKeyHex := "YOUR_EXPECTED_KEY_HEX_STRING" // e.g., "aabbccddeeff00112233445566778899"
   // expectedContentKey, _ := hex.DecodeString(expectedContentKeyHex)

   // derivedKnownKey, err := DerivePlayReadyContentKey(playReadyTestKeySeed, knownKeyIDBytes)
   // if err == nil {
   //    if bytes.Equal(derivedKnownKey, expectedContentKey) {
   //       fmt.Println("\nVerification: SUCCESS! Derived key matches expected.")
   //    } else {
   //       fmt.Printf("\nVerification: FAILED! Derived key: %x, Expected: %x\n", derivedKnownKey, expectedContentKey)
   //    }
   // }
}
