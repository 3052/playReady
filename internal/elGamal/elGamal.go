package elGamal

import (
   "crypto/ecdsa" // New import for ecdsa
   "crypto/elliptic"
   "fmt"
   "io"
   "math/big"
)

// NewElGamalECC creates a new ElGamalECC instance using the P256 curve.
func NewElGamalECC() *ElGamalECC {
   // Explicitly using P256 curve as assumed.
   return &ElGamalECC{
      Curve: elliptic.P256(),
   }
}

// Encrypt encrypts a message point M using the recipient's public key P. The
// ciphertext consists of two points:
// C1 = k * G (where k is a random integer)
// C2 = M + k * P (where P is the recipient's public key)
func (e *ElGamalECC) Encrypt(randReader io.Reader, pub, msg Point) (c1, c2 Point, err error) {
   // Generate an ephemeral ECDSA private key 'k'
   ephemeralPrivKey, err := ecdsa.GenerateKey(e.Curve, randReader)
   if err != nil {
      return Point{}, Point{}, fmt.Errorf("failed to generate ephemeral ECDSA key: %w", err)
   }
   // C1 = k * G. The public key of the ephemeral private key is k*G.
   c1 = Point{X: ephemeralPrivKey.PublicKey.X, Y: ephemeralPrivKey.PublicKey.Y}
   // Calculate k * P. Use the private scalar of the ephemeral key.
   kPx, kPy := e.Curve.ScalarMult(pub.X, pub.Y, ephemeralPrivKey.D.Bytes())
   // C2 = M + k * P
   c2x, c2y := e.Curve.Add(msg.X, msg.Y, kPx, kPy)
   c2 = Point{X: c2x, Y: c2y}
   return
}

// Decrypt decrypts the ciphertext (C1, C2) using the private key 'privKey'.
// The decrypted message point M is calculated as:
// M = C2 - priv * C1
func (e *ElGamalECC) Decrypt(privKey *ecdsa.PrivateKey, c1, c2 Point) (msg Point) {
   // Calculate priv * C1. Use privKey.D.Bytes() to get the private scalar.
   privC1x, privC1y := e.Curve.ScalarMult(c1.X, c1.Y, privKey.D.Bytes())
   // Invert privC1y to subtract priv * C1
   privC1yNeg := new(big.Int).Neg(privC1y)
   // Ensure the negated y-coordinate is within the field's prime modulus
   privC1yNeg.Mod(privC1yNeg, e.Curve.Params().P)
   msgX, msgY := e.Curve.Add(c2.X, c2.Y, privC1x, privC1yNeg)
   return Point{X: msgX, Y: msgY}
}

// Point represents a point on an elliptic curve.
type Point struct {
   X *big.Int
   Y *big.Int
}

// ElGamalECC represents the ElGamal ECC cryptosystem.
// This implementation specifically uses the P256 elliptic curve.
type ElGamalECC struct {
   Curve elliptic.Curve
}

// GenerateKeys generates a private and public key pair.
// Private key 'privKey' is a random ECDSA private key.
// Public key 'pub' is the point privKey.X, privKey.Y.
func (e *ElGamalECC) GenerateKeys(randReader io.Reader) (privKey *ecdsa.PrivateKey, pub Point, err error) {
   // Use ecdsa.GenerateKey which is the recommended way now.
   // It returns a full ECDSA private key which inherently contains the public key.
   privKey, err = ecdsa.GenerateKey(e.Curve, randReader)
   if err != nil {
      return nil, Point{}, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
   }

   pub = Point{X: privKey.PublicKey.X, Y: privKey.PublicKey.Y}

   return privKey, pub, nil
}
