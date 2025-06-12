package playReady

import (
   "bytes"
   "encoding/binary"
   "encoding/hex"
   "encoding/xml"
   "errors"
)

func (c *ContentKey) Decrypt(key EcKey, aux_keys *AuxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := c.ECC256(key)
      c.Integrity.Decode(decrypted)
      decrypted = decrypted[16:]
      copy(c.Key[:], decrypted)
      return nil
   case 6:
      return c.Scalable(key, aux_keys)
   }
   return errors.New("cant decrypt key")
}

func (c *ContentKey) Scalable(key EcKey, aux_keys *AuxKeys) error {
   rootKeyInfo := c.Value[:144]
   root_key := rootKeyInfo[128:]
   leaf_keys := c.Value[144:]
   var el_gamal ElGamal
   decrypted := el_gamal.Decrypt(rootKeyInfo[:128], key.Key.D)
   var (
      CI [16]byte
      CK [16]byte
   )
   for i := range 16 {
      CI[i] = decrypted[i*2]
      CK[i] = decrypted[i*2+1]
   }
   magic_constant_zero, err := hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
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

type ContentKey struct {
   KeyId      Guid
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   Integrity  Guid
   Key        [16]byte
}

type LocalDevice struct {
   CertificateChain Chain
   EncryptKey       EcKey
   SigningKey       EcKey
}

func (ld *LocalDevice) ParseLicense(data []byte) (*KeyData, error) {
   var response EnvelopeResponse
   err := xml.Unmarshal(data, &response)
   if err != nil {
      return nil, err
   }
   if fault := response.Body.Fault; fault != nil {
      return nil, errors.New(fault.Fault)
   }
   var license LicenseResponse
   err = license.Parse(response.
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
   if !bytes.Equal(license.ECCKeyObject.Value, ld.EncryptKey.PublicBytes()) {
      return nil, errors.New("license response is not for this device")
   }
   err = license.ContentKeyObject.Decrypt(ld.EncryptKey, license.AuxKeyObject)
   if err != nil {
      return nil, err
   }
   err = license.Verify(license.ContentKeyObject.Integrity.Guid())
   if err != nil {
      return nil, err
   }
   return &KeyData{
      license.ContentKeyObject.KeyId, license.ContentKeyObject.Key,
   }, nil
}

func XorKey(root, second []byte) []byte {
   data := make([]byte, len(second))
   copy(data, root)
   for i := range 16 {
      data[i] ^= second[i]
   }
   return data
}

func (c *ContentKey) ECC256(key EcKey) []byte {
   var el_gamal ElGamal
   return el_gamal.Decrypt(c.Value, key.Key.D)
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
