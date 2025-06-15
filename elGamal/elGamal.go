package elGamal

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/hex"
   "math/big"
   "slices"
)

// wikipedia.org/wiki/ElGamal_encryption#Decryption
func Decrypt(ciphertext []byte, privateKey *big.Int) []byte {
   g := elliptic.P256()
   // Unmarshal C1 component
   c1X := new(big.Int).SetBytes(ciphertext[:32])
   c1Y := new(big.Int).SetBytes(ciphertext[32:64])
   // Unmarshal C2 component
   c2X := new(big.Int).SetBytes(ciphertext[64:96])
   c2Y := new(big.Int).SetBytes(ciphertext[96:128])
   // Calculate shared secret s = C1^privateKey
   sX, sY := g.ScalarMult(c1X, c1Y, privateKey.Bytes())
   // Invert the point for subtraction
   sY.Neg(sY)
   sY.Mod(sY, g.Params().P)
   // Recover message point: M = C2 - s
   mX, mY := g.Add(c2X, c2Y, sX, sY)
   return append(mX.Bytes(), mY.Bytes()...)
}

// wikipedia.org/wiki/Windows_Media_DRM
const wmrm_public_key = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

// wikipedia.org/wiki/ElGamal_encryption#Key_generation
// The first party, Microsoft, generates a key pair
// The public key consists of the value h
func KeyGeneration() (*big.Int, *big.Int) {
   data, _ := hex.DecodeString(wmrm_public_key)
   return new(big.Int).SetBytes(data[:32]), new(big.Int).SetBytes(data[32:])
}

// wikipedia.org/wiki/ElGamal_encryption#Encryption
// A second party, Bob, encrypts a message M to Microsoft under their public key
func Encrypt(m *ecdsa.PublicKey, hX, hY *big.Int) []byte {
   // generator
   g := elliptic.P256()
   // choose an integer y randomly
   y := big.NewInt(1)
   // compute c1 := g^y
   c1X, c1Y := g.ScalarBaseMult(y.Bytes())
   // Calculate shared secret s = (h^y)
   sX, sY := g.ScalarMult(hX, hY, y.Bytes())
   // Second component C2 = M + s (point addition for elliptic curves)
   c2X, c2Y := g.Add(m.X, m.Y, sX, sY)
   return slices.Concat(c1X.Bytes(), c1Y.Bytes(), c2X.Bytes(), c2Y.Bytes())
}
