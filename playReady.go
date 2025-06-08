package playReady

import (
   "crypto/aes"
   "crypto/cipher"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/x509"
   "encoding/base64"
   "encoding/binary"
   "encoding/hex"
   "encoding/pem"
   "encoding/xml"
   "fmt"
   "github.com/deatil/go-cryptobin/mode"
   "math/big"
   "os"
)

type Config struct {
   Version    string `json:"client_version"`
   CertChain  string `json:"cert_chain"`
   SigningKey string `json:"signing"`
   EncryptKey string `json:"encrypt"`
}

type KeyData struct {
   KeyId Guid
   Key   Guid
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

type Guid struct {
   Data1 uint32 // little endian
   Data2 uint16 // little endian
   Data3 uint16 // little endian
   Data4 uint64 // big endian
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

func (k *Guid) Base64Decode(data string) error {
   decoded, err := base64.StdEncoding.DecodeString(data)
   if err != nil {
      return err
   }
   k.Decode(decoded)
   return nil
}

func (k *Guid) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, k.Data1)
   data = binary.BigEndian.AppendUint16(data, k.Data2)
   data = binary.BigEndian.AppendUint16(data, k.Data3)
   return binary.BigEndian.AppendUint64(data, k.Data4)
}

func (k *Guid) Bytes() []byte {
   var data []byte
   data = binary.LittleEndian.AppendUint32(data, k.Data1)
   data = binary.LittleEndian.AppendUint16(data, k.Data2)
   data = binary.LittleEndian.AppendUint16(data, k.Data3)
   return binary.BigEndian.AppendUint64(data, k.Data4)
}

func (k *Guid) Hex() string {
   data := k.Encode()
   dst := make([]byte, hex.EncodedLen(len(data)))
   hex.Encode(dst, data)
   return string(dst)
}

func XorKey(root, second []byte) []byte {
   data := make([]byte, len(second))
   copy(data, root)
   for i := range 16 {
      data[i] ^= second[i]
   }
   return data
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
type AcquireLicense struct {
   XmlNs     string    `xml:"xmlns,attr"`
   Challenge Challenge `xml:"challenge"`
}

type Algorithm struct {
   Algorithm string `xml:"Algorithm,attr"`
}

type Body struct {
   AcquireLicense AcquireLicense
}

type CertificateChains struct {
   CertificateChain string
}

type Challenge struct {
   Challenge InnerChallenge
}

type CipherData struct {
   CipherValue string
}

type ContentHeader struct {
   WrmHeader WrmHeader `xml:"WRMHEADER"`
}

type Data struct {
   CertificateChains CertificateChains
}

type EncryptedData struct {
   XmlNs            string `xml:"xmlns,attr"`
   Type             string `xml:"Type,attr"`
   EncryptionMethod Algorithm
   KeyInfo          KeyInfo
   CipherData       CipherData
}

type EncryptedKey struct {
   XmlNs            string `xml:"xmlns,attr"`
   EncryptionMethod Algorithm
   KeyInfo          EncryptedKeyInfo
   CipherData       CipherData
}

type EncryptedKeyInfo struct { // Renamed from KeyInfo
   XmlNs   string `xml:"xmlns,attr"`
   KeyName string
}

type Envelope struct {
   XMLName xml.Name `xml:"soap:Envelope"`
   Soap    string   `xml:"xmlns:soap,attr"`
   Body    Body     `xml:"soap:Body"`
}

type InnerChallenge struct { // Renamed from Challenge
   XmlNs     string `xml:"xmlns,attr"`
   La        La
   Signature Signature
}

type KeyInfo struct { // This is the chosen "KeyInfo" type
   XmlNs        string `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey
}

type ProtectInfo struct {
   KeyLen string `xml:"KEYLEN"`
   AlgId  string `xml:"ALGID"`
}

type Reference struct {
   Uri          string `xml:"URI,attr"`
   DigestValue  string
}

type Signature struct {
   SignedInfo     SignedInfo
   SignatureValue string
}

type SignedInfo struct {
   XmlNs                  string `xml:"xmlns,attr"`
   Reference              Reference
}

func (s *SignedInfo) New(digest []byte) {
   *s = SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      Reference: Reference{
         Uri: "#SignedData",
         DigestValue: base64.StdEncoding.EncodeToString(digest),
      },
   }
}

type WrmHeader struct {
   XmlNs   string        `xml:"xmlns,attr"`
   Version string        `xml:"version,attr"`
   Data    WrmHeaderData `xml:"DATA"`
}

type WrmHeaderData struct { // Renamed from DATA
   ProtectInfo ProtectInfo `xml:"PROTECTINFO"`
   Kid         string      `xml:"KID"`
}
var Fill Filler = '!'

func (a Aes) EncryptECB(key []byte, data []byte) []byte {
   block, _ := aes.NewCipher(key)
   ciphertext := make([]byte, len(data))
   ecbMode := mode.NewECBEncrypter(block)
   ecbMode.CryptBlocks(ciphertext, data)
   return ciphertext
}

func (a Aes) EncryptCbc(key *XmlKey, data []byte) ([]byte, error) {
   block, err := aes.NewCipher(key.AesKey[:])
   if err != nil {
      return nil, err
   }
   data = a.Pad(data)
   ciphertext := make([]byte, len(data))
   cipher.NewCBCEncrypter(block, key.AesIv[:]).CryptBlocks(ciphertext, data)
   return ciphertext, nil
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

func (e *EcKey) LoadBytes(data []byte) {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   var private ecdsa.PrivateKey
   private.D = new(big.Int).SetBytes(data)
   private.PublicKey = public
   e.Key = &private
}

func (e *EcKey) LoadFile(path string) error {
   keyFile, err := os.ReadFile(path)
   if err != nil {
      return err
   }
   block, _ := pem.Decode(keyFile)
   if block == nil {
      e.LoadBytes(keyFile)
      return nil
   }
   key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
   if err != nil {
      return err
   }
   e.Key = key.(*ecdsa.PrivateKey)
   return nil
}

func (e *EcKey) PublicBytes() []byte {
   SigningX, SigningY := e.Key.PublicKey.X.Bytes(), e.Key.PublicKey.Y.Bytes()
   SigningPublicKey := SigningX
   SigningPublicKey = append(SigningPublicKey, SigningY...)
   return SigningPublicKey
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

type Aes struct{}

func (Aes) Pad(data []byte) []byte {
   length := aes.BlockSize - len(data)%aes.BlockSize
   for high := byte(length); length >= 1; length-- {
      data = append(data, high)
   }
   return data
}

type WMRM struct{}

var WMRMPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func (e EcKey) Private() []byte {
   var data [32]byte
   e.Key.D.FillBytes(data[:])
   return data[:]
}

type EcKey struct {
   Key *ecdsa.PrivateKey
}

type Filler byte

// github.com/golang/go/issues/58454
func (f Filler) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

func (e *EcKey) New() error {
   var err error
   e.Key, err = ecdsa.GenerateKey(elliptic.P256(), Fill)
   if err != nil {
      return err
   }
   return nil
}

func (x *XmlKey) New() error {
   key, err := ecdsa.GenerateKey(elliptic.P256(), Fill)
   if err != nil {
      return err
   }
   x.PublicKey = key.PublicKey
   Aes := x.PublicKey.X.Bytes()
   n := copy(x.AesIv[:], Aes)
   Aes = Aes[n:]
   copy(x.AesKey[:], Aes)
   return nil
}

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

type Header struct {
   Record    *PlayReadyRecord
   Object    *PlayReadyObject
}

type ManufacturerInfo struct {
   Length uint32
   Value  string
}

func (m *ManufacturerInfo) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, m.Length)
   data = append(data, []byte(m.Value)...)

   return data
}

func (m *ManufacturerInfo) Decode(data []byte) (uint32, error) {
   m.Length = binary.BigEndian.Uint32(data)
   var n uint32 = 4

   paddedLength := (m.Length + 3) &^ 3

   m.Value = string(data[n:][:paddedLength])

   n += paddedLength

   return n, nil
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

type CertInfo struct {
   CertificateId [16]byte
   SecurityLevel uint32
   Flags         uint32
   Type          uint32
   Digest        [32]byte
   Expiry        uint32
   ClientId      [16]byte
}

func (c *CertInfo) New(SecurityLevel uint32, Digest []byte) {
   c.SecurityLevel = SecurityLevel
   c.Flags = 0
   c.Type = 2
   copy(c.Digest[:], Digest)
   c.Expiry = 4294967295
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
   data = append(data, m.ModelNumber.Encode()...)

   return data
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
