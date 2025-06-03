package crypto

import (
   "crypto/aes"
   "crypto/cipher"
   "github.com/deatil/go-cryptobin/mode"
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
