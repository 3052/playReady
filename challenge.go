package playReady

import (
   "41.neocities.org/playReady/challenge"
   "41.neocities.org/playReady/crypto"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/base64"
   "encoding/xml"
)

func (c *Chain) envelope(
   signing_key crypto.EcKey, kid string,
) (*challenge.Envelope, error) {
   var key crypto.XmlKey
   err := key.New()
   if err != nil {
      return nil, err
   }
   cipher_data, err := c.cipher_data(&key)
   if err != nil {
      return nil, err
   }
   var la_value challenge.La
   err = la_value.New(&key, cipher_data, kid)
   if err != nil {
      return nil, err
   }
   la_data, err := xml.Marshal(la_value)
   if err != nil {
      return nil, err
   }
   la_digest := sha256.Sum256(la_data)
   var signed_info challenge.SignedInfo
   signed_info.New(la_digest[:])
   signed_data, err := xml.Marshal(signed_info)
   if err != nil {
      return nil, err
   }
   signed_digest := sha256.Sum256(signed_data)
   r, s, err := ecdsa.Sign(crypto.Fill, signing_key.Key, signed_digest[:])
   if err != nil {
      return nil, err
   }
   sig := append(r.Bytes(), s.Bytes()...)
   return &challenge.Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: challenge.Body{
         AcquireLicense: challenge.AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: challenge.Challenge{
               Challenge: challenge.InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La: la_value,
                  Signature: challenge.Signature{
                     SignedInfo:     signed_info,
                     SignatureValue: base64.StdEncoding.EncodeToString(sig),
                  },
               },
            },
         },
      },
   }, nil
}

func (c *Chain) cipher_data(key *crypto.XmlKey) ([]byte, error) {
   data, err := xml.Marshal(challenge.Data{
      CertificateChains: challenge.CertificateChains{
         CertificateChain: base64.StdEncoding.EncodeToString(c.Encode()),
      },
   })
   if err != nil {
      return nil, err
   }
   var aes crypto.Aes
   ciphertext, err := aes.EncryptCbc(key, data)
   if err != nil {
      return nil, err
   }
   return append(key.AesIv[:], ciphertext...), nil
}
