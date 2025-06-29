package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "errors"
   "github.com/emmansun/gmsm/cbcmac"
   "github.com/emmansun/gmsm/padding"
   ecb "github.com/emmansun/gmsm/cipher"
)

func aesEcbEncrypt(data, key []byte) ([]byte, error) {
   block, err := aes.NewCipher(key)
   if err != nil {
      return nil, err
   }
   data1 := make([]byte, len(data))
   ecb.NewECBEncrypter(block).CryptBlocks(data1, data)
   return data1, nil
}

func (c *Chain) cipherData(key *xmlKey) ([]byte, error) {
   xmlData := xml.Data{
      CertificateChains: xml.CertificateChains{
         CertificateChain: c.Encode(),
      },
      Features: xml.Features{
         Feature: xml.Feature{"AESCBC"}, // SCALABLE
      },
   }
   data, err := xmlData.Marshal()
   if err != nil {
      return nil, err
   }
   data = padding.NewPKCS7Padding(aes.BlockSize).Pad(data)
   block, err := aes.NewCipher(key.aesKey())
   if err != nil {
      return nil, err
   }
   cipher.NewCBCEncrypter(block, key.aesIv()).CryptBlocks(data, data)
   return append(key.aesIv(), data...), nil
}

func (l *License) verify(data []byte) error {
   signature := new(Ftlv).size() + l.Signature.size()
   data = data[:len(data)-signature]
   block, err := aes.NewCipher(l.ContentKey.integrity())
   if err != nil {
      return err
   }
   data = cbcmac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.Signature.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}
