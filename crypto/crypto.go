package crypto

import (
   "crypto/aes"
   "crypto/cipher"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "crypto/x509"
   "encoding/hex"
   "encoding/pem"
   "fmt"
   "github.com/deatil/go-cryptobin/mode"
   "log"
   "math/big"
   "os"
)

func (WMRM) Points() (*big.Int, *big.Int, error) {
   bytes, err := hex.DecodeString(WMRMPublicKey)
   if err != nil {
      return nil, nil, fmt.Errorf("Error decoding hex string: %v", err)
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

func (a Aes) EncryptCBC(key XmlKey, data string) ([]byte, error) {
   block, err := aes.NewCipher(key.AesKey[:])

   if err != nil {
      return nil, err
   }

   padded := a.Pad([]byte(data))

   ciphertext := make([]byte, len(padded))
   mode := cipher.NewCBCEncrypter(block, key.AesIv[:])

   mode.CryptBlocks(ciphertext, padded)

   return ciphertext, nil
}

func (a Aes) EncryptECB(key []byte, data []byte) []byte {
   block, _ := aes.NewCipher(key)

   ciphertext := make([]byte, len(data))
   ecbMode := mode.NewECBEncrypter(block)

   ecbMode.CryptBlocks(ciphertext, data)

   return ciphertext
}

func (Aes) Pad(data []byte) []byte {
   length := aes.BlockSize - len(data)%aes.BlockSize
   for high := byte(length); length >= 1; length-- {
      data = append(data, high)
   }
   return data
}

type XmlKey struct {
   PublicKey     ecdsa.PublicKey
   AesKey, AesIv [16]byte
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


func (e *EcKey) New() error {
   var err error
   e.Key, err = ecdsa.GenerateKey(elliptic.P256(), fake_rand{})
   if err != nil {
      return err
   }
   return nil
}

type fake_rand struct{}

// github.com/golang/go/issues/58454
func (fake_rand) Read(data []byte) (int, error) {
   log.Println("fake_rand", len(data))
   return copy(data, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"), nil
}

func (x *XmlKey) New() error {
   key, err := ecdsa.GenerateKey(elliptic.P256(), fake_rand{})
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

func random_int(curveData elliptic.Curve) (*big.Int, error) {
   one := big.NewInt(1)
   maxInt := new(big.Int).Sub(curveData.Params().N, one)
   r, err := rand.Int(rand.Reader, maxInt)
   if err != nil {
      return nil, err
   }
   r.Add(r, one)
   return r, nil
}

func (ElGamal) Encrypt(
   PubX *big.Int, PubY *big.Int, plaintext XmlKey,
) ([]byte, error) {
   curveData := elliptic.P256()
   random, err := random_int(curveData)
   if err != nil {
      return nil, err
   }
   C1X, C1Y := curveData.ScalarMult(curveData.Params().Gx, curveData.Params().Gy, random.Bytes())
   C2XMulti, C2YMulti := curveData.ScalarMult(PubX, PubY, random.Bytes())
   C2X, C2Y := curveData.Add(plaintext.PublicKey.X, plaintext.PublicKey.Y, C2XMulti, C2YMulti)
   Encrypted := C1X.Bytes()
   Encrypted = append(Encrypted, C1Y.Bytes()...)
   Encrypted = append(Encrypted, C2X.Bytes()...)
   return append(Encrypted, C2Y.Bytes()...), nil
}
