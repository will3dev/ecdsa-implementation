package ecdsa

import (
	"math/big"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/rand"
)
/*
ECDSA SIGNING
1. the prover picks a random p and publishes their public key P as P = pG
2. The prover picks a message they want to sign and hashes it to get h = hash(message)
3. the prover picks a random scalar k and computes R = kG (this should be a point). Only need x value of R; r = R.x
4. The prover compuetes s = (h + rp)/k


SIGNATURE VERIFICATION

 */


type Point struct {
	X *big.Int
	Y *big.Int
}

type KeyObject struct {
	sk *big.Int
	pk *big.Int
}

type EcdsaSignature struct {
	publicKey Point
	h *big.Int // The hash of the message
	r *big.Int // point R.x of the random value 
	s *big.Int // the resulting signature
}

var (
	curve = elliptic.P256()
	G = Point {
		X: curve.Params().Gx,
		Y: curve.Params().Gy,
	}
	N = curve.Params().N
)


func generateRandomScalar() (*big.Int, error) {
	scalar, err := rand.Int(rand.Reader, N)
	if err != nil {
		return nil, err
	}

	if scalar.Cmp(big.NewInt(0)) == 0 {
		scalar = big.NewInt(1)
	}
	return scalar, nil
}

func hashMessage(message []byte) *big.Int {
	hash := sha256.Sum256(message)
	return new(big.Int).SetBytes(hash[:])
}

func generatePublicKey(privKey *big.Int) Point {
	x, y := curve.ScalarBaseMult(privKey.Bytes())
	return Point{X: x, Y: y}
}



func signMessage(message []byte, pubKey Point, privKey *big.Int, k *big.Int) EcdsaSignature {
	// hash message
	h := hashMessage(message)

	// Generate point R = kG
	Rx, Ry := curve.ScalarBaseMult(k.Bytes())
	R := Point{X:Rx, Y:Ry}
	
	r := R.X

	// compute s for k^-1 * (h + r * privKey) mod N
	rp := new(big.Int).Mul(r, privKey)
	rp.Mod(rp, N)

	hrp := new(big.Int).Add(h, rp)
	hrp.Mod(hrp, N)

	kInv := new(big.Int).ModInverse(k, N)

	s := new(big.Int).Mul(kInv, hrp)
	s.Mod(s, N)
	
	// generate and return the signature object
	Signature := EcdsaSignature {
		publicKey: pubKey,
		h: h,
		r: r,
		s: s
	}

	return Signature 
}


func verifySignature() {
	
}