package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "encoding/base64"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "github.com/deatil/go-cryptobin/mac"
)

func (c *ContentKey) decrypt(key *ecdsa.PrivateKey, auxKeys *auxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := elGamalDecrypt(c.Value, key)
      c.Integrity.Decode(decrypted)
      decrypted = decrypted[16:]
      copy(c.Key[:], decrypted)
      return nil
   case 6:
      return c.scalable(key, auxKeys)
   }
   return errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(key *ecdsa.PrivateKey, auxKeys *auxKeys) error {
   rootKeyInfo := c.Value[:144]
   rootKey := rootKeyInfo[128:]
   leafKeys := c.Value[144:]
   decrypted := elGamalDecrypt(rootKeyInfo[:128], key)
   var (
      ci [16]byte
      ck [16]byte
   )
   for i := range 16 {
      ci[i] = decrypted[i*2]
      ck[i] = decrypted[i*2+1]
   }
   magicConstantZero, err := c.magicConstantZero()
   if err != nil {
      return err
   }
   rgbUplinkXkey := xorKey(ck[:], magicConstantZero)
   contentKeyPrime, err := aesECBHandler(rgbUplinkXkey, ck[:], true)
   if err != nil {
      return err
   }
   auxKeyCalc, err := aesECBHandler(auxKeys.Keys[0].Key[:], contentKeyPrime, true)
   if err != nil {
      return err
   }
   var zero [16]byte
   upLinkXkey := xorKey(auxKeyCalc, zero[:])
   oSecondaryKey, err := aesECBHandler(rootKey, ck[:], true)
   if err != nil {
      return err
   }
   rgbKey, err := aesECBHandler(leafKeys, upLinkXkey, true)
   if err != nil {
      return err
   }
   rgbKey, err = aesECBHandler(rgbKey, oSecondaryKey, true)
   if err != nil {
      return err
   }
   c.Integrity.Decode(rgbKey[:])
   rgbKey = rgbKey[16:]
   copy(c.Key[:], rgbKey)
   return nil
}

// magicConstantZero returns a specific hex-decoded byte slice.
func (*ContentKey) magicConstantZero() ([]byte, error) {
   return hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
}

// decode decodes a byte slice into a ContentKey structure.
func (c *ContentKey) decode(data []byte) {
   c.KeyID.Decode(data[:])
   data = data[16:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Value = data[:c.Length]
}

type ContentKey struct {
   KeyID      GUID
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   Integrity  GUID
   Key        [16]byte
}
// ParseLicense parses a SOAP response containing a PlayReady license.
func ParseLicense(device *LocalDevice, data []byte) (*ContentKey, error) {
   var response xml.EnvelopeResponse
   err := response.Unmarshal(data)
   if err != nil {
      return nil, err
   }
   if fault := response.Body.Fault; fault != nil {
      return nil, errors.New(fault.Fault)
   }
   decoded, err := base64.StdEncoding.DecodeString(response.
      Body.
      AcquireLicenseResponse.
      AcquireLicenseResult.
      Response.
      LicenseResponse.
      Licenses.
      License,
   )
   if err != nil {
      return nil, err
   }
   var license licenseResponse
   err = license.decode(decoded)
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(license.eccKeyObject.Value, device.EncryptKey.PublicBytes()) {
      return nil, errors.New("license response is not for this device")
   }
   err = license.contentKeyObject.decrypt(
      device.EncryptKey[0], license.auxKeyObject,
   )
   if err != nil {
      return nil, err
   }
   err = license.verify(license.contentKeyObject.Integrity.GUID())
   if err != nil {
      return nil, err
   }
   return license.contentKeyObject, nil
}

// Encode encodes a LicenseResponse into a byte slice.
func (l *licenseResponse) encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsID[:]...)
   return append(data, l.OuterContainer.encode()...)
}

// Decode decodes a byte slice into a LicenseResponse structure.
func (l *licenseResponse) decode(data []byte) error {
   l.RawData = data
   n := copy(l.Magic[:], data)
   l.Offset = binary.BigEndian.Uint16(data[n:])
   n += 2
   l.Version = binary.BigEndian.Uint16(data[n:])
   n += 2
   n += copy(l.RightsID[:], data[n:])
   n += l.OuterContainer.decode(data[n:])

   var size int

   for size < int(l.OuterContainer.Length)-16 {
      var value ftlv
      i := value.decode(l.OuterContainer.Value[size:])
      switch xmrType(value.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         var j int
         for j < int(value.Length)-16 {
            var value1 ftlv
            k := value1.decode(value.Value[j:])

            switch xmrType(value1.Type) {
            case contentKeyEntryType: // 10
               l.contentKeyObject = &ContentKey{}
               l.contentKeyObject.decode(value1.Value)

            case deviceKeyEntryType: // 42
               l.eccKeyObject = &eccKey{}
               l.eccKeyObject.decode(value1.Value)

            case auxKeyEntryType: // 81
               l.auxKeyObject = &auxKeys{}
               l.auxKeyObject.decode(value1.Value)

            default:
               return errors.New("FTLV.type")
            }
            j += k
         }
      case signatureEntryType: // 11
         l.signatureObject = &signature{}
         l.signatureObject.decode(value.Value)
         l.signatureObject.Length = uint16(value.Length)

      default:
         return errors.New("FTLV.type")
      }
      size += i
   }

   return nil
}

// Verify verifies the license response signature.
func (l *licenseResponse) verify(contentIntegrity []byte) error {
   data := l.encode()
   data = data[:len(l.RawData)-int(l.signatureObject.Length)]
   block, err := aes.NewCipher(contentIntegrity)
   if err != nil {
      return err
   }
   data = mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.signatureObject.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

type licenseResponse struct {
   RawData          []byte
   Magic            [4]byte
   Offset           uint16
   Version          uint16
   RightsID         [16]byte
   OuterContainer   ftlv
   contentKeyObject *ContentKey
   eccKeyObject     *eccKey
   signatureObject  *signature
   auxKeyObject     *auxKeys
}
