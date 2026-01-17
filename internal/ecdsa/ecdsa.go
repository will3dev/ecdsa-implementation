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
	PublicKey Point
	H *big.Int // The hash of the message
	R *big.Int // point R.x of the random value
	S *big.Int // the resulting signature
}

var (
	curve = elliptic.P256()
	G = Point {
		X: curve.Params().Gx,
		Y: curve.Params().Gy,
	}
	N = curve.Params().N
)


func GenerateRandomScalar() (*big.Int, error) {
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

func GeneratePublicKey(privKey *big.Int) Point {
	x, y := curve.ScalarBaseMult(privKey.Bytes())
	return Point{X: x, Y: y}
}



func SignMessage(message []byte, pubKey Point, privKey *big.Int, k *big.Int) EcdsaSignature {
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
		PublicKey: pubKey,
		H: h,
		R: r,
		S: s,
	}

	return Signature 
}


func VerifySignature(sig EcdsaSignature) bool {
	// compute R` = s^-1 (hG + rP)
	rpX, rpY := curve.ScalarMult(sig.PublicKey.X, sig.PublicKey.Y, sig.R.Bytes())
	rP := Point{X: rpX, Y: rpY}

	hgX, hgY := curve.ScalarBaseMult(sig.H.Bytes())
	hG := Point{X: hgX, Y: hgY}

	sumX, sumY := curve.Add(hG.X, hG.Y, rP.X, rP.Y)

	sNew := new(big.Int).ModInverse(sig.S, N)

	sX, sY := curve.ScalarMult(sumX, sumY, sNew.Bytes())
	R := Point{X: sX, Y: sY}

	// check that R`.x == r from the signature
	return R.X.Cmp(sig.R) == 0
}