package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "encoding/binary"
   "errors"
   "github.com/emmansun/gmsm/cbcmac"
)

func (l *License) Decrypt(signEncrypt EcKey, data []byte) error {
   var envelope xml.EnvelopeResponse
   err := envelope.Unmarshal(data)
   if err != nil {
      return err
   }
   data = envelope.
      Body.
      AcquireLicenseResponse.
      AcquireLicenseResult.
      Response.
      LicenseResponse.
      Licenses.
      License
   err = l.decode(data)
   if err != nil {
      return err
   }
   if !bytes.Equal(l.EccKey.Value, signEncrypt.public()) {
      return errors.New("license response is not for this device")
   }
   err = l.ContentKey.decrypt(signEncrypt[0], l.AuxKeys)
   if err != nil {
      return err
   }
   return l.verify(data)
}

func (l *License) verify(data []byte) error {
   signature := new(Ftlv).size() + l.Signature.size()
   data = data[:len(data)-signature]
   block, err := aes.NewCipher(l.ContentKey.Integrity[:])
   if err != nil {
      return err
   }
   data = cbcmac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.Signature.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

func (c *CertificateInfo) New(securityLevel uint32, digest []byte) {
   copy(c.Digest[:], digest)
   // required, Max uint32, effectively never expires
   c.Expiry = 4294967295
   // required
   c.InfoType = 2
   c.SecurityLevel = securityLevel
}

func (c *CertificateInfo) encode() []byte {
   data := c.CertificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.SecurityLevel)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.InfoType)
   data = append(data, c.Digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Expiry)
   return append(data, c.ClientId[:]...)
}

func (c *CertificateInfo) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, c.encode())
}

func newFtlv(Flag, Type uint16, Value []byte) *Ftlv {
   return &Ftlv{
      Flag:   Flag,
      Type:   Type,
      Length: 8 + uint32(len(Value)),
      Value:  Value,
   }
}

func (f *Ftlv) size() int {
   n := 2 // Flag
   n += 2 // Type
   n += 4 // Length
   n += len(f.Value)
   return n
}

func (f *Ftlv) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint16(data, f.Flag)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}

func (k *KeyData) size() int {
   n := 2 // keyType
   n += 2 // length
   n += 4 // flags
   n += len(k.PublicKey)
   n += k.Usage.size()
   return n
}

func (l *LicenseSignature) size() int {
   n := 2 // type
   n += 2 // length
   n += len(l.Data)
   return n
}

type xmrType uint16

const (
   outerContainerEntryType                 xmrType = 1
   globalPolicyContainerEntryType          xmrType = 2
   playbackPolicyContainerEntryType        xmrType = 4
   minimumOutputProtectionLevelsEntryType  xmrType = 5
   explicitAnalogVideoProtectionEntryType  xmrType = 7
   analogVideoOPLEntryType                 xmrType = 8
   keyMaterialContainerEntryType           xmrType = 9
   contentKeyEntryType                     xmrType = 10
   signatureEntryType                      xmrType = 11
   serialNumberEntryType                   xmrType = 12
   rightsEntryType                         xmrType = 13
   expirationEntryType                     xmrType = 18
   issueDateEntryType                      xmrType = 19
   meteringEntryType                       xmrType = 22
   gracePeriodEntryType                    xmrType = 26
   sourceIdEntryType                       xmrType = 34
   restrictedSourceIdEntryType             xmrType = 40
   domainIdEntryType                       xmrType = 41
   deviceKeyEntryType                      xmrType = 42
   policyMetadataEntryType                 xmrType = 44
   optimizedContentKeyEntryType            xmrType = 45
   explicitDigitalAudioProtectionEntryType xmrType = 46
   expireAfterFirstUseEntryType            xmrType = 48
   digitalAudioOPLEntryType                xmrType = 49
   revocationInfoVersionEntryType          xmrType = 50
   embeddingBehaviorEntryType              xmrType = 51
   securityLevelEntryType                  xmrType = 52
   moveEnablerEntryType                    xmrType = 55
   uplinkKidEntryType                      xmrType = 59
   copyPoliciesContainerEntryType          xmrType = 60
   copyCountEntryType                      xmrType = 61
   removalDateEntryType                    xmrType = 80
   auxKeyEntryType                         xmrType = 81
   uplinkXEntryType                        xmrType = 82
   realTimeExpirationEntryType             xmrType = 85
   explicitDigitalVideoProtectionEntryType xmrType = 88
   digitalVideoOPLEntryType                xmrType = 89
   secureStopEntryType                     xmrType = 90
   copyUnknownObjectEntryType              xmrType = 65533
   globalPolicyUnknownObjectEntryType      xmrType = 65533
   playbackUnknownObjectEntryType          xmrType = 65533
   copyUnknownContainerEntryType           xmrType = 65534
   unknownContainersEntryType              xmrType = 65534
   playbackUnknownContainerEntryType       xmrType = 65534
)

func sign(key *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
   r, s, err := ecdsa.Sign(Fill('A'), key, hash)
   if err != nil {
      return nil, err
   }
   return append(r.Bytes(), s.Bytes()...), nil
}

func UuidOrGuid(data []byte) {
   // Data1 (first 4 bytes) - swap endianness in place
   data[0], data[3] = data[3], data[0]
   data[1], data[2] = data[2], data[1]
   // Data2 (next 2 bytes) - swap endianness in place
   data[4], data[5] = data[5], data[4]
   // Data3 (next 2 bytes) - swap endianness in place
   data[6], data[7] = data[7], data[6]
   // Data4 (last 8 bytes) - no change needed, so no operation here
}

func (f Fill) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

type Fill byte

func (l *License) decode(data []byte) error {
   n := copy(l.Magic[:], data)
   data = data[n:]
   l.Offset = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Version = binary.BigEndian.Uint16(data)
   data = data[2:]
   n = copy(l.RightsId[:], data)
   data = data[n:]
   var value1 Ftlv
   _, err := value1.decode(data) // Type 1
   if err != nil {
      return err
   }
   for len(value1.Value) >= 1 {
      var value2 Ftlv
      n, err = value2.decode(value1.Value)
      if err != nil {
         return err
      }
      value1.Value = value1.Value[n:]
      switch xmrType(value2.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         for len(value2.Value) >= 1 {
            var value3 Ftlv
            n, err = value3.decode(value2.Value)
            if err != nil {
               return err
            }
            value2.Value = value2.Value[n:]
            switch xmrType(value3.Type) {
            case contentKeyEntryType: // 10
               l.ContentKey = &ContentKey{}
               l.ContentKey.decode(value3.Value)
            case deviceKeyEntryType: // 42
               l.EccKey = &EccKey{}
               l.EccKey.decode(value3.Value)
            case auxKeyEntryType: // 81
               l.AuxKeys = &AuxKeys{}
               l.AuxKeys.decode(value3.Value)
            default:
               return errors.New("Ftlv.type")
            }
         }
      case signatureEntryType: // 11
         l.Signature = &LicenseSignature{}
         l.Signature.decode(value2.Value)
      default:
         return errors.New("Ftlv.type")
      }
   }
   return nil
}

type License struct {
   Magic      [4]byte           // 0
   Offset     uint16            // 1
   Version    uint16            // 2
   RightsId   [16]byte          // 3
   ContentKey *ContentKey       // 4.9.10
   EccKey     *EccKey           // 4.9.42
   AuxKeys    *AuxKeys          // 4.9.81
   Signature  *LicenseSignature // 4.11
}

func (f *Ftlv) decode(data []byte) (int, error) {
   f.Flag = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:f.Length]
   n += len(f.Value)
   return n, nil
}

type Ftlv struct {
   Flag   uint16 // this can be 0 or 1
   Type   uint16
   Length uint32
   Value  []byte
}

func (a *AuxKeys) decode(data []byte) {
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]
   a.Keys = make([]AuxKey, a.Count)
   for i := range a.Count {
      var key AuxKey
      n := key.decode(data)
      a.Keys[i] = key
      data = data[n:]
   }
}

type AuxKeys struct {
   Count uint16
   Keys  []AuxKey
}

func (a *AuxKey) decode(data []byte) int {
   a.Location = binary.BigEndian.Uint32(data)
   n := 4
   n += copy(a.Key[:], data[n:])
   return n
}

type AuxKey struct {
   Location uint32
   Key      [16]byte
}

func (l *LicenseSignature) decode(data []byte) {
   l.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Data = data
}

type LicenseSignature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

func (c *CertificateInfo) decode(data []byte) {
   n := copy(c.CertificateId[:], data)
   data = data[n:]
   c.SecurityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.InfoType = binary.BigEndian.Uint32(data)
   data = data[4:]
   n = copy(c.Digest[:], data)
   data = data[n:]
   c.Expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   copy(c.ClientId[:], data)
}

type CertificateInfo struct {
   CertificateId [16]byte
   SecurityLevel uint32
   Flags         uint32
   InfoType      uint32
   Digest        [32]byte
   Expiry        uint32
   ClientId      [16]byte // Client ID (can be used for license binding)
}
