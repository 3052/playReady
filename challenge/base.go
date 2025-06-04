package challenge

import (
   "41.neocities.org/playReady/certificate"
   "41.neocities.org/playReady/crypto"
   "41.neocities.org/playReady/header"
   "crypto/ecdsa"
   "crypto/rand"
   "crypto/sha256"
   "fmt"
   "strings"
)

type Challenge struct{}

func (c *Challenge) Create(certificateChain certificate.Chain, signingKey crypto.EcKey, header header.Header) (string, error) {
   var key crypto.XmlKey
   err := key.New()
   if err != nil {
      panic(err)
   }
   cipherData, err := c.CipherData(certificateChain, key)
   LA, err := c.LicenseAcquisition(key, cipherData, header)
   LAStr, err := LA.WriteToString()
   if err != nil {
      panic(err)
   }
   LAStr = strings.Replace(LAStr, "\n", "", -1)
   LADigest := sha256.Sum256([]byte(LAStr))
   SignedInfo := c.SignedInfo(LADigest[:])
   SignedStr, err := SignedInfo.WriteToString()
   if err != nil {
      panic(err)
   }
   SignedStr = strings.Replace(SignedStr, "\n", "", -1)
   SignedDigest := sha256.Sum256([]byte(SignedStr))
   r, s, err := ecdsa.Sign(rand.Reader, signingKey.Key, SignedDigest[:])
   if err != nil {
      fmt.Println("failed to sign")
   }
   sig := r.Bytes()
   sig = append(sig, s.Bytes()...)
   challenge := c.Root(LA, SignedInfo, sig, signingKey.PublicBytes())
   base, err := challenge.WriteToString()
   if err != nil {
      panic(err)
   }
   xmlHeader := `<?xml version="1.0" encoding="utf-8"?>`
   challengeStr := xmlHeader + base
   challengeStr = strings.Replace(challengeStr, "\n", "", -1)
   return challengeStr, nil
}
