import hashlib
import json
import time
import os
from typing import Dict, List

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

CHAIN_FILE = "audit_chain.json"
DIFFICULTY = 4


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def build_merkle_root(leaves: List[str]) -> str:
    if not leaves:
        return "0"

    level = leaves[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(sha256(level[i] + level[i + 1]))
        level = next_level

    return level[0]


def merkle_proof(leaves: List[str], target: str) -> List[str]:
    proof = []
    idx = leaves.index(target)
    level = leaves[:]

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        sibling = idx ^ 1
        proof.append(level[sibling])
        idx //= 2

        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(sha256(level[i] + level[i + 1]))
        level = next_level

    return proof


def verify_merkle_proof(target: str, proof: List[str], root: str) -> bool:
    computed = target
    for p in proof:
        computed = sha256(computed + p)
    return computed == root


class AuditBlock:
    def __init__(
        self,
        index: int,
        event_type: str,
        reference_id: str,
        actor: str,
        data_hash: str,
        previous_hash: str,
        timestamp: float,
        leaf_hashes: List[str],
        signature: bytes,
        nonce: int = 0,
        block_hash: str = None,
    ):
        self.index = index
        self.event_type = event_type
        self.reference_id = reference_id
        self.actor = actor
        self.data_hash = data_hash
        self.leaf_hashes = leaf_hashes
        self.merkle_root = build_merkle_root(leaf_hashes)
        self.signature = signature.hex()
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = block_hash or self.mine_block()

    def calculate_hash(self):
        payload = {
            "index": self.index,
            "event_type": self.event_type,
            "reference_id": self.reference_id,
            "actor": self.actor,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
        }
        return sha256(json.dumps(payload, sort_keys=True))

    def mine_block(self):
        prefix = "0" * DIFFICULTY
        while True:
            h = self.calculate_hash()
            if h.startswith(prefix):
                return h
            self.nonce += 1

    def to_dict(self):
        return {
            "index": self.index,
            "event_type": self.event_type,
            "reference_id": self.reference_id,
            "actor": self.actor,
            "leaf_hashes": self.leaf_hashes,
            "merkle_root": self.merkle_root,
            "signature": self.signature,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
        }

    @staticmethod
    def from_dict(d):
        return AuditBlock(
            index=d["index"],
            event_type=d["event_type"],
            reference_id=d["reference_id"],
            actor=d["actor"],
            data_hash="",
            leaf_hashes=d["leaf_hashes"],
            signature=bytes.fromhex(d["signature"]),
            timestamp=d["timestamp"],
            previous_hash=d["previous_hash"],
            nonce=d["nonce"],
            block_hash=d["hash"],
        )


class AuditBlockchain:
    def __init__(self):
        self.chain: List[AuditBlock] = []
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

        if os.path.exists(CHAIN_FILE):
            self._load_chain()
        else:
            self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = AuditBlock(
            index=0,
            event_type="GENESIS",
            reference_id="SYSTEM",
            actor="SYSTEM",
            data_hash="0",
            leaf_hashes=["0"],
            signature=b"",
            previous_hash="0",
            timestamp=time.time(),
        )
        self.chain.append(genesis)
        self._persist()

    def add_event(
        self,
        event_type: str,
        reference_id: str,
        actor: str,
        canonical_data: Dict,
    ):
        data_hash = sha256(json.dumps(canonical_data, sort_keys=True))
        signature = self.private_key.sign(
            data_hash.encode(),
            ec.ECDSA(hashes.SHA256()),
        )

        block = AuditBlock(
            index=len(self.chain),
            event_type=event_type,
            reference_id=reference_id,
            actor=actor,
            data_hash=data_hash,
            leaf_hashes=[data_hash],
            signature=signature,
            previous_hash=self.chain[-1].hash,
            timestamp=time.time(),
        )

        self.chain.append(block)
        self._persist()
        return block

    def verify_signature(self, block: AuditBlock) -> bool:
        try:
            self.public_key.verify(
                bytes.fromhex(block.signature),
                block.leaf_hashes[0].encode(),
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        except InvalidSignature:
            return False

    def _persist(self):
        with open(CHAIN_FILE, "w") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2)

    def _load_chain(self):
        with open(CHAIN_FILE, "r") as f:
            data = json.load(f)
            self.chain = [AuditBlock.from_dict(b) for b in data]
