package challenge

import (
   "41.neocities.org/playReady"
   "41.neocities.org/playReady/crypto"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/base64"
   "encoding/xml"
)

func get_cipher_data(
   chain *playReady.Chain, key *crypto.XmlKey,
) ([]byte, error) {
   data1, err := xml.Marshal(Data{
      CertificateChains: CertificateChains{
         CertificateChain: base64.StdEncoding.EncodeToString(chain.Encode()),
      },
   })
   if err != nil {
      return nil, err
   }
   var aes crypto.Aes
   ciphertext, err := aes.EncryptCbc(key, data1)
   if err != nil {
      return nil, err
   }
   return append(key.AesIv[:], ciphertext...), nil
}

func (e *Envelope) New(
   chain *playReady.Chain, signing_key crypto.EcKey, kid string,
) error {
   var key crypto.XmlKey
   err := key.New()
   if err != nil {
      return err
   }
   cipher_data, err := get_cipher_data(chain, &key)
   if err != nil {
      return err
   }
   var la_value La
   err = la_value.New(&key, cipher_data, kid)
   if err != nil {
      return err
   }
   la_data, err := xml.Marshal(la_value)
   if err != nil {
      return err
   }
   la_digest := sha256.Sum256(la_data)
   var signed_info SignedInfo
   signed_info.New(la_digest[:])
   signed_data, err := xml.Marshal(signed_info)
   if err != nil {
      return err
   }
   signed_digest := sha256.Sum256(signed_data)
   r, s, err := ecdsa.Sign(crypto.Fill, signing_key.Key, signed_digest[:])
   if err != nil {
      return err
   }
   sig := append(r.Bytes(), s.Bytes()...)
   *e = Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: Body{
         AcquireLicense: AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: Challenge{
               Challenge: InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La: la_value,
                  Signature: Signature{
                     SignedInfo:     signed_info,
                     SignatureValue: base64.StdEncoding.EncodeToString(sig),
                  },
               },
            },
         },
      },
   }
   return nil
}

