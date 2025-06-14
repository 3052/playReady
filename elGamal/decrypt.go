package elGamal

import (
   "crypto/elliptic"
   "math/big"
)

/*
wikipedia.org/wiki/ElGamal_encryption#Decryption
private key x and public key h are created in a.XmlKey.New
private key is discarded

d.TestRakuten calls c.LocalDevice.EncryptKey.LoadBytes
d.TestRakuten calls d.ParseLicense with c.LocalDevice
d.ParseLicense calls a.ContentKey.Decrypt with c.LocalDevice.EncryptKey[0]
a.ContentKey.Decrypt is called with a private key
*/
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
