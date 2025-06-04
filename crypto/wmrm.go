package crypto

import (
   "crypto/aes"
   "crypto/cipher"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "encoding/hex"
   "fmt"
   "github.com/deatil/go-cryptobin/mode"
   "math/big"
)

type Aes struct{}

func (a Aes) EncryptCBC(key XmlKey, data string) ([]byte, error) {
   block, err := aes.NewCipher(key.AesKey[:])

   if err != nil {
      return nil, err
   }

   padded := a.Pad([]byte(data))

   ciphertext := make([]byte, len(padded))
   mode := cipher.NewCBCEncrypter(block, key.AesIv[:])

   mode.CryptBlocks(ciphertext, padded)

   return ciphertext, nil
}

func (a Aes) EncryptECB(key []byte, data []byte) []byte {
   block, _ := aes.NewCipher(key)

   ciphertext := make([]byte, len(data))
   ecbMode := mode.NewECBEncrypter(block)

   ecbMode.CryptBlocks(ciphertext, data)

   return ciphertext
}

func (Aes) Pad(data []byte) []byte {
   length := aes.BlockSize - len(data)%aes.BlockSize
   for high := byte(length); length >= 1; length-- {
      data = append(data, high)
   }
   return data
}
type XmlKey struct {
   PublicKey     ecdsa.PublicKey
   AesKey, AesIv [16]byte
}

func (x *XmlKey) New() error {
   key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

   if err != nil {
      return err
   }

   x.PublicKey = key.PublicKey

   Aes := x.PublicKey.X.Bytes()

   n := copy(x.AesIv[:], Aes)

   Aes = Aes[n:]

   copy(x.AesKey[:], Aes)

   return nil
}
type WMRM struct{}

var WMRMPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func (WMRM) Points() (*big.Int, *big.Int, error) {
   bytes, err := hex.DecodeString(WMRMPublicKey)

   if err != nil {
      fmt.Println("Error decoding hex string:", err)
   }

   x := new(big.Int).SetBytes(bytes[:32])
   y := new(big.Int).SetBytes(bytes[32:])

   return x, y, nil
}
