package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "encoding/binary"
   "errors"
   "github.com/deatil/go-cryptobin/cryptobin/crypto"
   "github.com/deatil/go-cryptobin/mac"
)

// aesCBCHandler performs AES CBC encryption/decryption with PKCS7 padding.
// Encrypts if encrypt is true, decrypts otherwise.
func aesCBCHandler(data, key, iv []byte, encrypt bool) ([]byte, error) {
   if encrypt {
      bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
         Aes().CBC().PKCS7Padding().Encrypt()
      return bin.ToBytes(), bin.Error()
   } else {
      bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
         Aes().CBC().PKCS7Padding().Decrypt()
      return bin.ToBytes(), bin.Error()
   }
}

// aesECBHandler performs AES ECB encryption/decryption.
// Encrypts if encrypt is true, decrypts otherwise.
func aesECBHandler(data, key []byte, encrypt bool) ([]byte, error) {
   if encrypt {
      bin := crypto.FromBytes(data).WithKey(key).
         Aes().ECB().NoPadding().Encrypt()
      return bin.ToBytes(), bin.Error()
   } else {
      bin := crypto.FromBytes(data).WithKey(key).
         Aes().ECB().NoPadding().Decrypt()
      return bin.ToBytes(), bin.Error()
   }
}

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

type License struct {
   Magic          [4]byte           // 0
   Offset         uint16            // 1
   Version        uint16            // 2
   RightsID       [16]byte          // 3
   GlobalPolicy   struct{}          // 4.2
   PlaybackPolicy struct{}          // 4.4
   ContentKey     *ContentKey       // 4.9.10
   eccKey         *eccKey           // 4.9.42
   auxKeys        *auxKeys          // 4.9.81
   signature      *licenseSignature // 4.11
}

func (l *License) verify(data []byte) error {
   signature := new(ftlv).size() + l.signature.size()
   data = data[:len(data)-signature]
   block, err := aes.NewCipher(l.ContentKey.Integrity[:])
   if err != nil {
      return err
   }
   data = mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.signature.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

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
   if !bytes.Equal(l.eccKey.Value, signEncrypt.public()) {
      return errors.New("license response is not for this device")
   }
   err = l.ContentKey.decrypt(signEncrypt[0], l.auxKeys)
   if err != nil {
      return err
   }
   return l.verify(data)
}

func (l *License) decode(data []byte) error {
   n := copy(l.Magic[:], data)
   data = data[n:]
   l.Offset = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Version = binary.BigEndian.Uint16(data)
   data = data[2:]
   n = copy(l.RightsID[:], data)
   data = data[n:]
   var outer ftlv
   _, err := outer.decode(data) // Type 1
   if err != nil {
      return err
   }
   for len(outer.Value) >= 1 {
      var inner ftlv
      n, err = inner.decode(outer.Value)
      if err != nil {
         return err
      }
      outer.Value = outer.Value[n:]
      switch xmrType(inner.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         for len(inner.Value) >= 1 {
            var key ftlv
            n, err = key.decode(inner.Value)
            if err != nil {
               return err
            }
            inner.Value = inner.Value[n:]
            switch xmrType(key.Type) {
            case contentKeyEntryType: // 10
               l.ContentKey = &ContentKey{}
               l.ContentKey.decode(key.Value)
            case deviceKeyEntryType: // 42
               l.eccKey = &eccKey{}
               l.eccKey.decode(key.Value)
            case auxKeyEntryType: // 81
               l.auxKeys = &auxKeys{}
               l.auxKeys.decode(key.Value)
            default:
               return errors.New("ftlv.type")
            }
         }
      case signatureEntryType: // 11
         l.signature = &licenseSignature{}
         l.signature.decode(inner.Value)
      default:
         return errors.New("ftlv.type")
      }
   }
   return nil
}

// Decode decodes a byte slice into an AuxKey structure.
func (a *auxKey) decode(data []byte) int {
   a.Location = binary.BigEndian.Uint32(data)
   n := 4
   n += copy(a.Key[:], data[n:])
   return n
}

type auxKey struct {
   Location uint32
   Key      [16]byte
}

type auxKeys struct {
   Count uint16
   Keys  []auxKey
}

// Decode decodes a byte slice into an AuxKeys structure.
func (a *auxKeys) decode(data []byte) {
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]
   a.Keys = make([]auxKey, a.Count)
   for i := range a.Count {
      var key auxKey
      n := key.decode(data)
      a.Keys[i] = key
      data = data[n:]
   }
}

func (c *certificateInfo) New(securityLevel uint32, digest []byte) {
   copy(c.digest[:], digest)
   // required, Max uint32, effectively never expires
   c.expiry = 4294967295
   // required
   c.infoType = 2
   c.securityLevel = securityLevel
}

func (c *certificateInfo) encode() []byte {
   data := c.certificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.securityLevel)
   data = binary.BigEndian.AppendUint32(data, c.flags)
   data = binary.BigEndian.AppendUint32(data, c.infoType)
   data = append(data, c.digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.expiry)
   return append(data, c.clientId[:]...)
}

func (c *certificateInfo) decode(data []byte) {
   n := copy(c.certificateId[:], data)
   data = data[n:]
   c.securityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.infoType = binary.BigEndian.Uint32(data)
   data = data[4:]
   n = copy(c.digest[:], data)
   data = data[n:]
   c.expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   copy(c.clientId[:], data)
}

type certificateInfo struct {
   certificateId [16]byte
   securityLevel uint32
   flags         uint32
   infoType      uint32
   digest        [32]byte
   expiry        uint32
   clientId      [16]byte // Client ID (can be used for license binding)
}

func (c *certificateInfo) ftlv(Flag, Type uint16) *ftlv {
   return newFtlv(Flag, Type, c.encode())
}

// It returns the number of bytes consumed.
func (f *features) decode(data []byte) int {
   f.entries = binary.BigEndian.Uint32(data)
   n := 4
   f.features = make([]uint32, f.entries)
   for i := range f.entries { // Correctly iterate up to f.entries
      f.features[i] = binary.BigEndian.Uint32(data[n:])
      n += 4
   }
   return n
}

func newFtlv(Flag, Type uint16, Value []byte) *ftlv {
   return &ftlv{
      Flag:   Flag,
      Type:   Type,
      Length: 8 + uint32(len(Value)),
      Value:  Value,
   }
}

type ftlv struct {
   Flag   uint16 // this can be 0 or 1
   Type   uint16
   Length uint32
   Value  []byte
}

func (f *ftlv) decode(data []byte) (int, error) {
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

func (f *ftlv) size() int {
   n := 2 // Flag
   n += 2 // Type
   n += 4 // Length
   n += len(f.Value)
   return n
}

func (f *ftlv) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint16(data, f.Flag)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}

func (k *keyData) size() int {
   n := 2 // keyType
   n += 2 // length
   n += 4 // flags
   n += len(k.publicKey)
   n += k.usage.size()
   return n
}

func (l *licenseSignature) size() int {
   n := 2 // type
   n += 2 // length
   n += len(l.Data)
   return n
}

type licenseSignature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

func (l *licenseSignature) decode(data []byte) {
   l.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Data = data
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
   sourceIDEntryType                       xmrType = 34
   restrictedSourceIDEntryType             xmrType = 40
   domainIDEntryType                       xmrType = 41
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
   uplinkKIDEntryType                      xmrType = 59
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
