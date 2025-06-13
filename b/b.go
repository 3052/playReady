package b

import "encoding/binary"

type Signature struct {
   Type            uint16
   SignatureLength uint16
   SignatureData   []byte
   IssuerLength    uint32
   IssuerKey       []byte
}

func (s *Signature) New(Signature, SigningKey []byte) {
   s.Type = 1
   s.SignatureLength = uint16(len(Signature))
   s.SignatureData = make([]byte, len(Signature))
   copy(s.SignatureData, Signature)
   s.IssuerLength = uint32(len(SigningKey))
   s.IssuerKey = make([]byte, len(SigningKey))
   copy(s.IssuerKey, SigningKey)
}

func (s *Signature) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint16(data, s.Type)
   data = binary.BigEndian.AppendUint16(data, s.SignatureLength)
   data = append(data, s.SignatureData...)
   data = binary.BigEndian.AppendUint32(data, s.IssuerLength*8)
   return append(data, s.IssuerKey...)
}

func (s *Signature) Decode(data []byte) error {
   s.Type = binary.BigEndian.Uint16(data)
   data = data[2:]

   s.SignatureLength = binary.BigEndian.Uint16(data)
   data = data[2:]

   s.SignatureData = make([]byte, int(s.SignatureLength))
   n := copy(s.SignatureData[:], data)
   data = data[n:]

   s.IssuerLength = binary.BigEndian.Uint32(data)
   data = data[4:]

   s.IssuerKey = make([]byte, int(s.IssuerLength)/8)
   copy(s.IssuerKey[:], data)

   return nil
}
