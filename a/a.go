package a

import (
   "41.neocities.org/playReady/elGamal"
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "github.com/deatil/go-cryptobin/cryptobin/crypto"
   "github.com/deatil/go-cryptobin/mac"
   "math/big"
)

func (c *ContentKey) Decrypt(key *ecdsa.PrivateKey, auxKeys *auxKeys) error {
   switch c.cipherType {
   case 3:
      decrypted := elGamal.Decrypt(c.value, key)
      c.Integrity.decode(decrypted)
      decrypted = decrypted[16:]
      copy(c.Key[:], decrypted)
      return nil
   case 6:
      return c.scalable(key, auxKeys)
   }
   return errors.New("cant decrypt key")
}

func (c *ContentKey) scalable(key *ecdsa.PrivateKey, auxKeys *auxKeys) error {
   rootKeyInfo := c.value[:144]
   rootKey := rootKeyInfo[128:]
   leafKeys := c.value[144:]
   decrypted := elGamal.Decrypt(rootKeyInfo[:128], key)
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
   contentKeyPrime, err := aesEcbEncrypt(rgbUplinkXkey, ck[:])
   if err != nil {
      return err
   }
   auxKeyCalc, err := aesEcbEncrypt(auxKeys.keys[0].key[:], contentKeyPrime)
   if err != nil {
      return err
   }
   var zero [16]byte
   upLinkXkey := xorKey(auxKeyCalc, zero[:])
   oSecondaryKey, err := aesEcbEncrypt(rootKey, ck[:])
   if err != nil {
      return err
   }
   rgbKey, err := aesEcbEncrypt(leafKeys, upLinkXkey)
   if err != nil {
      return err
   }
   rgbKey, err = aesEcbEncrypt(rgbKey, oSecondaryKey)
   if err != nil {
      return err
   }
   c.Integrity.decode(rgbKey[:])
   rgbKey = rgbKey[16:]
   copy(c.Key[:], rgbKey)
   return nil
}

func (e *EcKey) LoadBytes(data []byte) {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   var private ecdsa.PrivateKey
   private.D = new(big.Int).SetBytes(data)
   private.PublicKey = public
   e[0] = &private
}

// pkg.go.dev/crypto/ecdsa#PublicKey
func (e *EcKey) PublicBytes() []byte {
   return append(e[0].PublicKey.X.Bytes(), e[0].PublicKey.Y.Bytes()...)
}

func (e *EcKey) New() error {
   var err error
   e[0], err = ecdsa.GenerateKey(elliptic.P256(), Fill('A'))
   if err != nil {
      return err
   }
   return nil
}

func (e EcKey) Private() []byte {
   return e[0].D.Bytes()
}

type Fill byte

// github.com/golang/go/issues/58454
func (f Fill) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

type guid struct {
   data1 uint32 // little endian
   data2 uint16 // little endian
   data3 uint16 // little endian
   data4 uint64 // big endian
}

func (g *guid) Uuid() []byte {
   data := binary.BigEndian.AppendUint32(nil, g.data1)
   data = binary.BigEndian.AppendUint16(data, g.data2)
   data = binary.BigEndian.AppendUint16(data, g.data3)
   return binary.BigEndian.AppendUint64(data, g.data4)
}

func (g *guid) Guid() []byte {
   data := binary.LittleEndian.AppendUint32(nil, g.data1)
   data = binary.LittleEndian.AppendUint16(data, g.data2)
   data = binary.LittleEndian.AppendUint16(data, g.data3)
   return binary.BigEndian.AppendUint64(data, g.data4)
}

func (g *guid) decode(data []byte) {
   g.data1 = binary.LittleEndian.Uint32(data)
   data = data[4:]
   g.data2 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   g.data3 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   g.data4 = binary.BigEndian.Uint64(data)
}

func (l *LicenseResponse) encode() []byte {
   data := l.magic[:]
   data = binary.BigEndian.AppendUint16(data, l.offset)
   data = binary.BigEndian.AppendUint16(data, l.version)
   data = append(data, l.rightsId[:]...)
   return append(data, l.outerContainer.Encode()...)
}

type LicenseResponse struct {
   rawData          []byte
   magic            [4]byte
   offset           uint16
   version          uint16
   rightsId         [16]byte
   outerContainer   FTLV
   ContentKeyObject *ContentKey
   EccKeyObject     *eccKey
   signatureObject  *signature
   AuxKeyObject     *auxKeys
}

type auxKeys struct {
   count uint16
   keys  []auxKey
}

type auxKey struct {
   location uint32
   key      [16]byte
}

type eccKey struct {
   curve  uint16
   length uint16
   Value  []byte
}

func (a *auxKeys) decode(data []byte) {
   a.count = binary.BigEndian.Uint16(data)
   data = data[2:]
   for range a.count {
      var key auxKey
      n := key.decode(data)
      a.keys = append(a.keys, key)
      data = data[n:]
   }
}

func (a *auxKey) decode(data []byte) int {
   a.location = binary.BigEndian.Uint32(data)
   data = data[4:]
   return copy(a.key[:], data) + 4
}

func (e *eccKey) decode(data []byte) {
   e.curve = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.length = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Value = make([]byte, e.length)
   copy(e.Value, data)
}

func (f *FTLV) Encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, f.flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.length)
   return append(data, f.Value...)
}

func (f *FTLV) Decode(data []byte) int {
   f.flags = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:][:f.length-8]
   n += int(f.length) - 8
   return n
}

type FTLV struct {
   flags  uint16
   Type   uint16
   length uint32
   Value  []byte
}

func (f *FTLV) New(flags, Type int, value []byte) {
   f.flags = uint16(flags)
   f.Type = uint16(Type)
   f.length = uint32(len(value) + 8)
   f.Value = value
}

type ContentKey struct {
   KeyId      guid
   keyType    uint16
   cipherType uint16
   length     uint16
   value      []byte
   Integrity  guid
   Key        [16]byte
}

func (c *ContentKey) decode(data []byte) {
   c.KeyId.decode(data[:])
   data = data[16:]
   c.keyType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.cipherType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.length = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.value = make([]byte, c.length)
   copy(c.value[:], data)
}

type xmrType uint16

const (
   outerContainerEntryType                 xmrType = 1
   globalPolicyContainerEntryType          xmrType = 2
   playbackPolicyContainerEntryType        xmrType = 4
   minimumOutputProtectionLevelsEntryType  xmrType = 5
   explicitAnalogVideoProtectionEntryType  xmrType = 7
   analogVideoOplEntryType                 xmrType = 8
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
   digitalAudioOplEntryType                xmrType = 49
   revocationInfoVersionEntryType          xmrType = 50
   embeddingBehaviorEntryType              xmrType = 51
   securityLevelEntryType                  xmrType = 52
   moveEnablerEntryType                    xmrType = 55
   uplinkKIDEntryType                      xmrType = 59
   copyPoliciesContainerEntryType          xmrType = 60
   copyCountEntryType                      xmrType = 61
   removalDateEntryType                    xmrType = 80
   auxKeyEntryType                         xmrType = 81
   uplinkxEntryType                        xmrType = 82
   realTimeExpirationEntryType             xmrType = 85
   explicitDigitalVideoProtectionEntryType xmrType = 88
   digitalVideoOplEntryType                xmrType = 89
   secureStopEntryType                     xmrType = 90
   copyUnknownObjectEntryType              xmrType = 65533
   globalPolicyUnknownObjectEntryType      xmrType = 65533
   playbackUnknownObjectEntryType          xmrType = 65533
   copyUnknownContainerEntryType           xmrType = 65534
   unknownContainersEntryType              xmrType = 65534
   playbackUnknownContainerEntryType       xmrType = 65534
)

func xorKey(root, second []byte) []byte {
   data := make([]byte, len(second))
   copy(data, root)
   for i := range 16 {
      data[i] ^= second[i]
   }
   return data
}

func (*ContentKey) magicConstantZero() ([]byte, error) {
   return hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
}

func (l *LicenseResponse) Decode(data []byte) error {
   l.rawData = make([]byte, len(data))
   copy(l.rawData, data)

   n := copy(l.magic[:], data)
   l.offset = binary.BigEndian.Uint16(data[n:])
   n += 2
   l.version = binary.BigEndian.Uint16(data[n:])
   n += 2
   n += copy(l.rightsId[:], data[n:])
   n += l.outerContainer.Decode(data[n:])

   var size int

   for size < int(l.outerContainer.length)-16 {
      var value FTLV
      i := value.Decode(l.outerContainer.Value[size:])
      switch xmrType(value.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         var j int
         for j < int(value.length)-16 {
            var value1 FTLV
            k := value1.Decode(value.Value[j:])

            switch xmrType(value1.Type) {
            case contentKeyEntryType: // 10
               l.ContentKeyObject = &ContentKey{}
               l.ContentKeyObject.decode(value1.Value)

            case deviceKeyEntryType: // 42
               l.EccKeyObject = &eccKey{}
               l.EccKeyObject.decode(value1.Value)

            case auxKeyEntryType: // 81
               l.AuxKeyObject = &auxKeys{}
               l.AuxKeyObject.decode(value1.Value)

            default:
               return errors.New("FTLV.type")
            }
            j += k
         }
      case signatureEntryType: // 11
         l.signatureObject = &signature{}
         l.signatureObject.decode(value.Value)
         l.signatureObject.length = uint16(value.length)

      default:
         return errors.New("FTLV.type")
      }
      size += i
   }

   return nil
}

func (s *signature) decode(data []byte) {
   s.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.length = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.data = data
}

type signature struct {
   Type   uint16
   length uint16
   data   []byte
}

func (l *LicenseResponse) Verify(contentIntegrity []byte) error {
   data := l.encode()
   data = data[:len(l.rawData)-int(l.signatureObject.length)]
   block, err := aes.NewCipher(contentIntegrity)
   if err != nil {
      return err
   }
   data = mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.signatureObject.data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

func aesEcbEncrypt(data, key []byte) ([]byte, error) {
   bin := crypto.FromBytes(data).WithKey(key).
      Aes().ECB().NoPadding().Encrypt()
   return bin.ToBytes(), bin.Error()
}

func AesCbcPaddingEncrypt(data, key, iv []byte) ([]byte, error) {
   bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
      Aes().CBC().PKCS7Padding().Encrypt()
   return bin.ToBytes(), bin.Error()
}

type EcKey [1]*ecdsa.PrivateKey

type XmlKey struct {
   PublicKey ecdsa.PublicKey
   x         [32]byte
}

func (x *XmlKey) New() {
   x.PublicKey.X, x.PublicKey.Y = elliptic.P256().ScalarBaseMult([]byte{1})
   x.PublicKey.X.FillBytes(x.x[:])
}

func (x *XmlKey) AesIv() []byte {
   return x.x[:16]
}

func (x *XmlKey) AesKey() []byte {
   return x.x[16:]
}
