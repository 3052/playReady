package playReady

import (
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "encoding/binary"
   "errors"
   "github.com/deatil/go-cryptobin/cryptobin/crypto"
   "github.com/deatil/go-cryptobin/mac"
)

// decode decodes a byte slice into the features structure.
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

func (k *keyInfo) decode(data []byte) {
   k.entries = binary.BigEndian.Uint32(data)
   data = data[4:]
   k.keys = make([]keyData, k.entries)
   for i := range k.entries { // Correctly iterate up to k.entries
      var key keyData
      n := key.decode(data) // Decode each keyData object
      k.keys[i] = key
      data = data[n:] // Advance data slice for the next key
   }
}

func (f *ftlv) size() int {
   n := 2 // Flags
   n += 2 // Type
   n += 4 // Length
   n += len(f.Value)
   return n
}

func (f *features) size() int {
   n := 4 // entries
   n += 4 * len(f.features)
   return n
}

func (k *keyData) size() int {
   n := 2 // keyType
   n += 2 // length
   n += 4 // flags
   n += len(k.publicKey)
   n += k.usage.size()
   return n
}

func (k *keyInfo) size() int {
   n := 4 // entries
   for _, key := range k.keys {
      n += key.size()
   }
   return n
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

type features struct {
   entries  uint32   // Number of feature entries
   features []uint32 // Slice of feature IDs
}

type keyData struct {
   keyType   uint16
   length    uint16 // Total length of the keyData structure
   flags     uint32
   publicKey [64]byte // ECDSA P256 public key (X and Y coordinates)
   usage     features // Features indicating key usage
}

type keyInfo struct {
   entries uint32    // Number of key entries
   keys    []keyData // Slice of keyData structures
}

func sign(key *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
   r, s, err := ecdsa.Sign(Fill('A'), key, hash)
   if err != nil {
      return nil, err
   }
   return append(r.Bytes(), s.Bytes()...), nil
}

func (c *certificateInfo) New(securityLevel uint32, digest []byte) {
   c.securityLevel = securityLevel
   c.infoType = 2 // required
   copy(c.digest[:], digest)
   c.expiry = 4294967295 // required, Max uint32, effectively never expires
}

func (f *ftlv) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, f.Flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
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

func (l *License) verify(contentIntegrity []byte) error {
   data := l.encode()
   data = data[:len(data)-int(l.signature.Length)]
   block, err := aes.NewCipher(contentIntegrity)
   if err != nil {
      return err
   }
   data = mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.signature.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

func (l *License) encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsID[:]...)
   return append(data, l.OuterContainer.encode()...)
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
   l.OuterContainer.decode(data)
   var n1 int
   for n1 < int(l.OuterContainer.Length)-16 {
      var value ftlv
      n3, err := value.decode(l.OuterContainer.Value[n1:])
      if err != nil {
         return err
      }
      n1 += n3
      switch xmrType(value.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         var n2 int
         for n2 < int(value.Length)-16 {
            var value1 ftlv
            n4, err := value1.decode(value.Value[n2:])
            if err != nil {
               return err
            }
            n2 += n4
            switch xmrType(value1.Type) {
            case contentKeyEntryType: // 10
               l.ContentKey = &ContentKey{}
               l.ContentKey.decode(value1.Value)
            case deviceKeyEntryType: // 42
               l.eccKey = &eccKey{}
               l.eccKey.decode(value1.Value)
            case auxKeyEntryType: // 81
               l.auxKeyObject = &auxKeys{}
               l.auxKeyObject.decode(value1.Value)
            default:
               return errors.New("FTLV.type")
            }
         }
      case signatureEntryType: // 11
         l.signature = &licenseSignature{}
         l.signature.decode(value.Value)
         l.signature.Length = uint16(value.Length)
      default:
         return errors.New("FTLV.type")
      }
   }
   return nil
}

type License struct {
   Magic          [4]byte
   Offset         uint16
   Version        uint16
   RightsID       [16]byte
   OuterContainer ftlv
   ContentKey     *ContentKey
   eccKey         *eccKey
   signature      *licenseSignature
   auxKeyObject   *auxKeys
}

func (l *licenseSignature) decode(data []byte) {
   l.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Data = data
}

type licenseSignature struct {
   Type   uint16
   Length uint16
   Data   []byte
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

type auxKeys struct {
   Count uint16
   Keys  []auxKey
}

type auxKey struct {
   Location uint32
   Key      [16]byte
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

func (f Fill) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

type Fill byte

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

// Decode decodes a byte slice into an AuxKey structure.
func (a *auxKey) decode(data []byte) int {
   a.Location = binary.BigEndian.Uint32(data)
   n := 4
   n += copy(a.Key[:], data[n:])
   return n
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
