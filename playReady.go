package playReady

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/binary"
   "encoding/hex"
   "fmt"
   "github.com/deatil/go-cryptobin/cryptobin/crypto"
   "math/big"
)

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

type KeyData struct {
   KeyId Guid
   Key   [16]byte
}

type Guid struct {
   Data1 uint32 // little endian
   Data2 uint16 // little endian
   Data3 uint16 // little endian
   Data4 uint64 // big endian
}

func (k *Guid) Uuid() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, k.Data1)
   data = binary.BigEndian.AppendUint16(data, k.Data2)
   data = binary.BigEndian.AppendUint16(data, k.Data3)
   return binary.BigEndian.AppendUint64(data, k.Data4)
}

func (k *Guid) Guid() []byte {
   var data []byte
   data = binary.LittleEndian.AppendUint32(data, k.Data1)
   data = binary.LittleEndian.AppendUint16(data, k.Data2)
   data = binary.LittleEndian.AppendUint16(data, k.Data3)
   return binary.BigEndian.AppendUint64(data, k.Data4)
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

func (c *CertInfo) New(SecurityLevel uint32, Digest []byte) {
   c.SecurityLevel = SecurityLevel
   c.Flags = 0
   c.Type = 2
   copy(c.Digest[:], Digest)
   c.Expiry = 4294967295
}

type CertInfo struct {
   CertificateId [16]byte
   SecurityLevel uint32
   Flags         uint32
   Type          uint32
   Digest        [32]byte
   Expiry        uint32
   // NOTE SOME SERVERS, FOR EXAMPLE
   // rakuten.tv
   // WILL LOCK LICENSE TO THE FIRST DEVICE, USING "ClientId" TO DETECT, SO BE
   // CAREFUL USING A VALUE HERE
   ClientId [16]byte
}

func (c *CertInfo) Decode(data []byte) error {
   n := copy(c.CertificateId[:], data)
   data = data[n:]
   c.SecurityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Type = binary.BigEndian.Uint32(data)
   data = data[4:]
   n = copy(c.Digest[:], data)
   data = data[n:]
   c.Expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   copy(c.ClientId[:], data)
   return nil
}

func (c *CertInfo) Encode() []byte {
   data := c.CertificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.SecurityLevel)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.Type)
   data = append(data, c.Digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Expiry)
   return append(data, c.ClientId[:]...)
}

func aes_ecb_encrypt(data, key []byte) ([]byte, error) {
   bin := crypto.FromBytes(data).WithKey(key).
      Aes().ECB().NoPadding().Encrypt()
   return bin.ToBytes(), bin.Error()
}

func aes_cbc_padding_encrypt(data, key, iv []byte) ([]byte, error) {
   bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
      Aes().CBC().PKCS7Padding().Encrypt()
   return bin.ToBytes(), bin.Error()
}

func (e *EcKey) LoadBytes(data []byte) {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   var private ecdsa.PrivateKey
   private.D = new(big.Int).SetBytes(data)
   private.PublicKey = public
   e.Key = &private
}

func (e *EcKey) PublicBytes() []byte {
   SigningX, SigningY := e.Key.PublicKey.X.Bytes(), e.Key.PublicKey.Y.Bytes()
   SigningPublicKey := SigningX
   SigningPublicKey = append(SigningPublicKey, SigningY...)
   return SigningPublicKey
}

func (e EcKey) Private() []byte {
   var data [32]byte
   e.Key.D.FillBytes(data[:])
   return data[:]
}

type EcKey struct {
   Key *ecdsa.PrivateKey
}

type AuxKeys struct {
   Count uint16
   Keys  []AuxKey
}

func (a *AuxKeys) Decode(data []byte) error {
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]

   for range a.Count {
      var Key AuxKey

      i, err := Key.Decode(data)

      if err != nil {
         return err
      }

      a.Keys = append(a.Keys, Key)

      data = data[i:]
   }
   return nil
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

type FTLV struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
}

type Manufacturer struct {
   Flags            uint32
   ManufacturerName ManufacturerInfo
   ModelName        ManufacturerInfo
   ModelNumber      ManufacturerInfo
}

func (m *Manufacturer) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, m.Flags)
   data = append(data, m.ManufacturerName.Encode()...)
   data = append(data, m.ModelName.Encode()...)
   return append(data, m.ModelNumber.Encode()...)
}

func (m *Manufacturer) Decode(data []byte) error {
   m.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   n, err := m.ManufacturerName.Decode(data)
   if err != nil {
      return err
   }
   data = data[n:]
   n, err = m.ModelName.Decode(data)
   if err != nil {
      return err
   }
   data = data[n:]
   _, err = m.ModelNumber.Decode(data)
   if err != nil {
      return err
   }
   return nil
}

type AuxKey struct {
   Location uint32
   Key      [16]byte
}

func (a *AuxKey) Decode(data []byte) (int, error) {
   a.Location = binary.BigEndian.Uint32(data)
   data = data[4:]

   n := copy(a.Key[:], data)

   return n + 4, nil
}

type ECCKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

func (e *ECCKey) Decode(data []byte) error {
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]

   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]

   e.Value = make([]byte, e.Length)
   copy(e.Value, data)

   return nil
}

type CertificateChains struct {
   CertificateChain string
}

type Data struct {
   CertificateChains CertificateChains
}

type XmlKey struct {
   AesIv     [16]byte
   AesKey    [16]byte
   PublicKey ecdsa.PublicKey
}

func (WMRM) Points() (*big.Int, *big.Int, error) {
   bytes, err := hex.DecodeString(WMRMPublicKey)
   if err != nil {
      return nil, nil, fmt.Errorf("decoding hex string: %v", err)
   }
   x := new(big.Int).SetBytes(bytes[:32])
   y := new(big.Int).SetBytes(bytes[32:])
   return x, y, nil
}

type ElGamal struct{}

func (ElGamal) Decrypt(ciphertext []byte, PrivateKey *big.Int) []byte {
   curveData := elliptic.P256()

   x1, y1 := new(big.Int).SetBytes(ciphertext[:32]), new(big.Int).SetBytes(ciphertext[32:64])
   x2, y2 := new(big.Int).SetBytes(ciphertext[64:96]), new(big.Int).SetBytes(ciphertext[96:128])

   SX, SY := curveData.ScalarMult(x1, y1, PrivateKey.Bytes())

   NegSY := new(big.Int).Sub(curveData.Params().P, SY)

   NegSY.Mod(NegSY, curveData.Params().P)

   PX, PY := curveData.Add(x2, y2, SX, NegSY)

   Decrypted := PX.Bytes()

   return append(Decrypted, PY.Bytes()...)
}

type WMRM struct{}

var WMRMPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func (ElGamal) Encrypt(
   PubX *big.Int, PubY *big.Int, plaintext *XmlKey,
) ([]byte, error) {
   curveData := elliptic.P256()
   curve_int := big.NewInt(1)
   C1X, C1Y := curveData.ScalarMult(
      curveData.Params().Gx, curveData.Params().Gy, curve_int.Bytes(),
   )
   C2XMulti, C2YMulti := curveData.ScalarMult(PubX, PubY, curve_int.Bytes())
   C2X, C2Y := curveData.Add(
      plaintext.PublicKey.X, plaintext.PublicKey.Y, C2XMulti, C2YMulti,
   )
   Encrypted := C1X.Bytes()
   Encrypted = append(Encrypted, C1Y.Bytes()...)
   Encrypted = append(Encrypted, C2X.Bytes()...)
   return append(Encrypted, C2Y.Bytes()...), nil
}

type Device struct {
   MaxLicenseSize       uint32
   MaxHeaderSize        uint32
   MaxLicenseChainDepth uint32
}

func (d *Device) New() {
   d.MaxLicenseSize = uint32(10240)
   d.MaxHeaderSize = uint32(15360)
   d.MaxLicenseChainDepth = uint32(2)
}

func (d *Device) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, d.MaxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.MaxHeaderSize)
   return binary.BigEndian.AppendUint32(data, d.MaxLicenseChainDepth)
}

func (f *FTLV) New(Flags, Type int, Value []byte) {
   f.Flags = uint16(Flags)
   f.Type = uint16(Type)
   f.Length = uint32(len(Value) + 8)
   f.Value = Value
}

type ManufacturerInfo struct {
   Length uint32
   Value  string
}

func (m *ManufacturerInfo) Encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.Length)
   return append(data, []byte(m.Value)...)
}

func (m *ManufacturerInfo) Decode(data []byte) (uint32, error) {
   m.Length = binary.BigEndian.Uint32(data)
   var n uint32 = 4
   padded_length := (m.Length + 3) &^ 3
   m.Value = string(data[n:][:padded_length])
   return n + padded_length, nil
}

type ObjType uint16

const (
   BASIC ObjType = iota + 1
   DOMAIN
   PC
   DEVICE
   FEATURE
   KEY
   MANUFACTURER
   SIGNATURE
   SILVERLIGHT
   METERING
   EXTDATASIGNKEY
   EXTDATACONTAINER
   EXTDATASIGNATURE
   EXTDATA_HWIO
   SERVER
   SECURITY_VERSION
   SECURITY_VERSION_2
)

type PlayReadyObject struct {
   Type   uint16
   Length uint16
   Data   string
}

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
