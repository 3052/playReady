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

func (c *ContentKey) Decrypt(key *ecdsa.PrivateKey, aux_keys *AuxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := elGamal.Decrypt(c.Value, key.D)
      c.Integrity.Decode(decrypted)
      decrypted = decrypted[16:]
      copy(c.Key[:], decrypted)
      return nil
   case 6:
      return c.Scalable(key, aux_keys)
   }
   return errors.New("cant decrypt key")
}

// pkg.go.dev/crypto/ecdsa#PublicKey
func (e *EcKey) PublicBytes() []byte {
   return append(e[0].PublicKey.X.Bytes(), e[0].PublicKey.Y.Bytes()...)
}

// pkg.go.dev/crypto/ecdsa#PublicKey
func (x *XmlKey) New() error {
   key, err := ecdsa.GenerateKey(elliptic.P256(), Fill)
   if err != nil {
      return err
   }
   data := key.PublicKey.X.Bytes()
   n := copy(x.AesIv[:], data)
   data = data[n:]
   copy(x.AesKey[:], data)
   x.PublicKey = key.PublicKey
   return nil
}

type XmlKey struct {
   AesIv     [16]byte
   AesKey    [16]byte
   PublicKey ecdsa.PublicKey
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

func (e *EcKey) New() error {
   var err error
   e[0], err = ecdsa.GenerateKey(elliptic.P256(), Fill)
   if err != nil {
      return err
   }
   return nil
}

func (e EcKey) Private() []byte {
   var data [32]byte
   e[0].D.FillBytes(data[:])
   return data[:]
}

type Filler byte

// github.com/golang/go/issues/58454
func (f Filler) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

var Fill Filler = '!'

type Guid struct {
   Data1 uint32 // little endian
   Data2 uint16 // little endian
   Data3 uint16 // little endian
   Data4 uint64 // big endian
}

func (k *Guid) Uuid() []byte {
   data := binary.BigEndian.AppendUint32(nil, k.Data1)
   data = binary.BigEndian.AppendUint16(data, k.Data2)
   data = binary.BigEndian.AppendUint16(data, k.Data3)
   return binary.BigEndian.AppendUint64(data, k.Data4)
}

func (k *Guid) Guid() []byte {
   data := binary.LittleEndian.AppendUint32(nil, k.Data1)
   data = binary.LittleEndian.AppendUint16(data, k.Data2)
   data = binary.LittleEndian.AppendUint16(data, k.Data3)
   return binary.BigEndian.AppendUint64(data, k.Data4)
}

type Signature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

func (k *Guid) Decode(data []byte) {
   k.Data1 = binary.LittleEndian.Uint32(data)
   data = data[4:]
   k.Data2 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   k.Data3 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   k.Data4 = binary.BigEndian.Uint64(data)
}

func (l *LicenseResponse) Encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsId[:]...)
   return append(data, l.OuterContainer.Encode()...)
}

func (s *Signature) Decode(data []byte) error {
   s.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Data = make([]byte, s.Length)
   copy(s.Data, data)
   return nil
}

type LicenseResponse struct {
   RawData          []byte
   Magic            [4]byte
   Offset           uint16
   Version          uint16
   RightsId         [16]byte
   OuterContainer   FTLV
   ContentKeyObject *ContentKey
   ECCKeyObject     *ECCKey
   SignatureObject  *Signature
   AuxKeyObject     *AuxKeys
}

type AuxKeys struct {
   Count uint16
   Keys  []AuxKey
}

type AuxKey struct {
   Location uint32
   Key      [16]byte
}

type ECCKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

type FTLV struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
}

func (a *AuxKeys) Decode(data []byte) {
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]
   for range a.Count {
      var key AuxKey
      n := key.Decode(data)
      a.Keys = append(a.Keys, key)
      data = data[n:]
   }
}

func (a *AuxKey) Decode(data []byte) int {
   a.Location = binary.BigEndian.Uint32(data)
   data = data[4:]
   return copy(a.Key[:], data) + 4
}

func (e *ECCKey) Decode(data []byte) {
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]

   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]

   e.Value = make([]byte, e.Length)
   copy(e.Value, data)
}

func (f *FTLV) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint16(data, f.Flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}

func (f *FTLV) Decode(data []byte) (uint32, error) {
   var n uint32
   f.Flags = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:][:f.Length-8]
   n += f.Length - 8
   return n, nil
}

func (f *FTLV) New(Flags, Type int, Value []byte) {
   f.Flags = uint16(Flags)
   f.Type = uint16(Type)
   f.Length = uint32(len(Value) + 8)
   f.Value = Value
}

type ContentKey struct {
   KeyId      Guid
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   Integrity  Guid
   Key        [16]byte
}

func (c *ContentKey) Decode(data []byte) error {
   c.KeyId.Decode(data[:])
   data = data[16:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.Value = make([]byte, c.Length)

   copy(c.Value[:], data)

   return nil
}

type XmrType uint16

const (
   OUTER_CONTAINER_ENTRY_TYPE                   XmrType = 1
   GLOBAL_POLICY_CONTAINER_ENTRY_TYPE           XmrType = 2
   PLAYBACK_POLICY_CONTAINER_ENTRY_TYPE         XmrType = 4
   MINIMUM_OUTPUT_PROTECTION_LEVELS_ENTRY_TYPE  XmrType = 5
   EXPLICIT_ANALOG_VIDEO_PROTECTION_ENTRY_TYPE  XmrType = 7
   ANALOG_VIDEO_OPL_ENTRY_TYPE                  XmrType = 8
   KEY_MATERIAL_CONTAINER_ENTRY_TYPE            XmrType = 9
   CONTENT_KEY_ENTRY_TYPE                       XmrType = 10
   SIGNATURE_ENTRY_TYPE                         XmrType = 11
   SERIAL_NUMBER_ENTRY_TYPE                     XmrType = 12
   RIGHTS_ENTRY_TYPE                            XmrType = 13
   EXPIRATION_ENTRY_TYPE                        XmrType = 18
   ISSUEDATE_ENTRY_TYPE                         XmrType = 19
   METERING_ENTRY_TYPE                          XmrType = 22
   GRACEPERIOD_ENTRY_TYPE                       XmrType = 26
   SOURCEID_ENTRY_TYPE                          XmrType = 34
   RESTRICTED_SOURCEID_ENTRY_TYPE               XmrType = 40
   DOMAIN_ID_ENTRY_TYPE                         XmrType = 41
   DEVICE_KEY_ENTRY_TYPE                        XmrType = 42
   POLICY_METADATA_ENTRY_TYPE                   XmrType = 44
   OPTIMIZED_CONTENT_KEY_ENTRY_TYPE             XmrType = 45
   EXPLICIT_DIGITAL_AUDIO_PROTECTION_ENTRY_TYPE XmrType = 46
   EXPIRE_AFTER_FIRST_USE_ENTRY_TYPE            XmrType = 48
   DIGITAL_AUDIO_OPL_ENTRY_TYPE                 XmrType = 49
   REVOCATION_INFO_VERSION_ENTRY_TYPE           XmrType = 50
   EMBEDDING_BEHAVIOR_ENTRY_TYPE                XmrType = 51
   SECURITY_LEVEL_ENTRY_TYPE                    XmrType = 52
   MOVE_ENABLER_ENTRY_TYPE                      XmrType = 55
   UPLINK_KID_ENTRY_TYPE                        XmrType = 59
   COPY_POLICIES_CONTAINER_ENTRY_TYPE           XmrType = 60
   COPY_COUNT_ENTRY_TYPE                        XmrType = 61
   REMOVAL_DATE_ENTRY_TYPE                      XmrType = 80
   AUX_KEY_ENTRY_TYPE                           XmrType = 81
   UPLINKX_ENTRY_TYPE                           XmrType = 82
   REAL_TIME_EXPIRATION_ENTRY_TYPE              XmrType = 85
   EXPLICIT_DIGITAL_VIDEO_PROTECTION_ENTRY_TYPE XmrType = 88
   DIGITAL_VIDEO_OPL_ENTRY_TYPE                 XmrType = 89
   SECURESTOP_ENTRY_TYPE                        XmrType = 90
   COPY_UNKNOWN_OBJECT_ENTRY_TYPE               XmrType = 65533
   GLOBAL_POLICY_UNKNOWN_OBJECT_ENTRY_TYPE      XmrType = 65533
   PLAYBACK_UNKNOWN_OBJECT_ENTRY_TYPE           XmrType = 65533
   COPY_UNKNOWN_CONTAINER_ENTRY_TYPE            XmrType = 65534
   UNKNOWN_CONTAINERS_ENTRY_TYPE                XmrType = 65534
   PLAYBACK_UNKNOWN_CONTAINER_ENTRY_TYPE        XmrType = 65534
)

func (p *PlayReadyRecord) Decode(data []byte) bool {
   p.Length = binary.LittleEndian.Uint32(data)
   if int(p.Length) > len(data) {
      return false
   }
   data = data[4:]
   p.Count = binary.LittleEndian.Uint16(data)
   data = data[2:]
   p.Data = data
   return true
}

type PlayReadyRecord struct {
   Length uint32
   Count  uint16
   Data   []byte
}

func XorKey(root, second []byte) []byte {
   data := make([]byte, len(second))
   copy(data, root)
   for i := range 16 {
      data[i] ^= second[i]
   }
   return data
}

func (*ContentKey) magic_constant_zero() ([]byte, error) {
   return hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
}

func (l *LicenseResponse) Decode(data []byte) error {
   l.RawData = make([]byte, len(data))
   copy(l.RawData, data)

   n := copy(l.Magic[:], data)
   l.Offset = binary.BigEndian.Uint16(data[n:])
   n += 2
   l.Version = binary.BigEndian.Uint16(data[n:])
   n += 2
   n += copy(l.RightsId[:], data[n:])

   j, err := l.OuterContainer.Decode(data[n:])

   if err != nil {
      return err
   }
   n += int(j)

   var size uint32

   for size < l.OuterContainer.Length-16 {
      var value FTLV
      i, err := value.Decode(l.OuterContainer.Value[int(size):])
      if err != nil {
         return err
      }
      switch XmrType(value.Type) {
      case GLOBAL_POLICY_CONTAINER_ENTRY_TYPE: // 2
         // Rakuten
      case PLAYBACK_POLICY_CONTAINER_ENTRY_TYPE: // 4
         // Rakuten
      case KEY_MATERIAL_CONTAINER_ENTRY_TYPE: // 9
         var j uint32
         for j < value.Length-16 {
            var value1 FTLV
            k, err := value1.Decode(value.Value[j:])
            if err != nil {
               return err
            }
            switch XmrType(value1.Type) {
            case CONTENT_KEY_ENTRY_TYPE: // 10
               l.ContentKeyObject = &ContentKey{}
               err = l.ContentKeyObject.Decode(value1.Value)
               if err != nil {
                  return err
               }
            
            case DEVICE_KEY_ENTRY_TYPE: // 42
               l.ECCKeyObject = &ECCKey{}
               l.ECCKeyObject.Decode(value1.Value)
            
            case AUX_KEY_ENTRY_TYPE: // 81
               l.AuxKeyObject = &AuxKeys{}
               l.AuxKeyObject.Decode(value1.Value)
            
            default:
               return errors.New("FTLV.Type")
            }
            j += k
         }
      case SIGNATURE_ENTRY_TYPE: // 11
         l.SignatureObject = &Signature{}
         err := l.SignatureObject.Decode(value.Value)
         l.SignatureObject.Length = uint16(value.Length)
         if err != nil {
            return err
         }
      default:
         return errors.New("FTLV.Type")
      }
      size += i
   }

   return nil
}

func (l *LicenseResponse) Verify(content_integrity []byte) error {
   data := l.Encode()
   data = data[:len(l.RawData)-int(l.SignatureObject.Length)]
   block, err := aes.NewCipher(content_integrity)
   if err != nil {
      return err
   }
   data = mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.SignatureObject.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

func aes_ecb_encrypt(data, key []byte) ([]byte, error) {
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

func (c *ContentKey) Scalable(key *ecdsa.PrivateKey, aux_keys *AuxKeys) error {
   rootKeyInfo := c.Value[:144]
   root_key := rootKeyInfo[128:]
   leaf_keys := c.Value[144:]
   decrypted := elGamal.Decrypt(rootKeyInfo[:128], key.D)
   var (
      CI [16]byte
      CK [16]byte
   )
   for i := range 16 {
      CI[i] = decrypted[i*2]
      CK[i] = decrypted[i*2+1]
   }
   magic_constant_zero, err := c.magic_constant_zero()
   if err != nil {
      return err
   }
   rgb_uplink_xkey := XorKey(CK[:], magic_constant_zero)
   content_key_prime, err := aes_ecb_encrypt(rgb_uplink_xkey, CK[:])
   if err != nil {
      return err
   }
   aux_key_calc, err := aes_ecb_encrypt(
      aux_keys.Keys[0].Key[:], content_key_prime,
   )
   if err != nil {
      return err
   }
   var zero [16]byte
   up_link_xkey := XorKey(aux_key_calc, zero[:])
   o_secondary_key, err := aes_ecb_encrypt(root_key, CK[:])
   if err != nil {
      return err
   }
   rgb_key, err := aes_ecb_encrypt(leaf_keys, up_link_xkey)
   if err != nil {
      return err
   }
   rgb_key, err = aes_ecb_encrypt(rgb_key, o_secondary_key)
   if err != nil {
      return err
   }
   c.Integrity.Decode(rgb_key[:])
   rgb_key = rgb_key[16:]
   copy(c.Key[:], rgb_key)
   return nil
}
