package playReady

import (
   "encoding/binary"
   "encoding/hex"
   "errors"
   "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func (c *ContentKey) Scalable(key EcKey, aux_keys *AuxKeys) error {
   rootKeyInfo := c.Value[:144]
   root_key := rootKeyInfo[128:]
   leaf_keys := c.Value[144:]
   var el_gamal ElGamal
   decrypted := el_gamal.Decrypt(rootKeyInfo[:128], key.Key.D)
   var CI [16]byte
   var CK [16]byte
   for i := range 16 {
      CI[i] = decrypted[i*2]
      CK[i] = decrypted[i*2+1]
   }
   magic_constant_zero, err := hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
   if err != nil {
      return err
   }
   rgb_uplink_xkey := XorKey(CK[:], magic_constant_zero)
   var zero [16]byte
   bin := crypto.New().Aes().ECB().NoPadding()
   bin = bin.WithData(rgb_uplink_xkey).WithKey(CK[:]).Encrypt()
   if err := bin.Error(); err != nil {
      return err
   }
   content_key_prime := bin.ToBytes()
   bin = bin.WithData(aux_keys.Keys[0].Key[:]).
      WithKey(content_key_prime).Encrypt()
   if err := bin.Error(); err != nil {
      return err
   }
   aux_key_calc := bin.ToBytes()
   up_link_xkey := XorKey(aux_key_calc, zero[:])
   bin = bin.WithData(root_key).WithKey(CK[:]).Encrypt()
   if err := bin.Error(); err != nil {
      return err
   }
   o_secondary_key := bin.ToBytes()
   bin = bin.WithData(leaf_keys).WithKey(up_link_xkey).Encrypt()
   if err := bin.Error(); err != nil {
      return err
   }
   rgb_key := bin.ToBytes()
   bin = bin.WithData(rgb_key).WithKey(o_secondary_key).Encrypt()
   if err := bin.Error(); err != nil {
      return err
   }
   rgb_key = bin.ToBytes()
   c.Integrity.Decode(rgb_key[:])
   rgb_key = rgb_key[16:]
   c.Key.Decode(rgb_key[:])
   return nil
}

func XorKey(root, second []byte) []byte {
   data := make([]byte, len(second))
   copy(data, root)
   for i := range 16 {
      data[i] ^= second[i]
   }
   return data
}

func (c *ContentKey) Decrypt(key EcKey, aux_keys *AuxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := c.ECC256(key)
      c.Integrity.Decode(decrypted)
      decrypted = decrypted[16:]
      c.Key.Decode(decrypted)
      return nil
   case 6:
      return c.Scalable(key, aux_keys)
   }
   return errors.New("cant decrypt key")
}

func (c *ContentKey) ECC256(key EcKey) []byte {
   var el_gamal ElGamal
   return el_gamal.Decrypt(c.Value, key.Key.D)
}

type ContentKey struct {
   KeyId      Guid
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   Integrity  Guid
   Key        Guid
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
