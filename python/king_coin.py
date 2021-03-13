"""
A simple setup for crypto-based transactions without decentralization
"""

from typing import Tuple, Optional, Dict

from dataclasses import dataclass

from collections import defaultdict

import binascii
import os

from enum import Enum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding


def generate_keys(key_size: int = 512) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=crypto_default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


class TransactionType(Enum):
    mint = "mint"
    transfer = "transfer"


@dataclass(frozen=True)
class Transaction:
    type: TransactionType
    content: bytes
    currency: str
    party_from: str
    amount: float
    signature: bytes
    party_to: Optional[str] = None


class CoinMaker:
    def __init__(self, coin_name: str, name: str) -> None:
        self.name = name     # will be removed in later versions (in favour of decentralized design)
        self.coin_name = coin_name
        self.pool: float = 0
        self.private_key, self.public_key = generate_keys()
        self.number_of_bytes = 3

    def get_public_key(self) -> rsa.RSAPublicKey:
        return self.public_key

    def mint_single_coin(self) -> Transaction:
        coin = binascii.b2a_hex(os.urandom(self.number_of_bytes))   # generate random coin id
        signature = self.private_key.sign(coin,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                      salt_length=padding.PSS.MAX_LENGTH),
                                          algorithm=hashes.SHA256())
        transaction = Transaction(content=coin,
                                  type=TransactionType.mint,
                                  currency=self.coin_name,
                                  party_from=self.name,
                                  amount=1,
                                  signature=signature)
        self.pool += 1
        return transaction

    def send_single_coin_to(self, to_name: str, to_public_key: rsa.RSAPublicKey, coin_id: bytes) -> Transaction:
        coin_id_and_public_key = bytearray(coin_id)
        coin_id_and_public_key.extend(to_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        signature = self.private_key.sign(coin_id_and_public_key,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                      salt_length=padding.PSS.MAX_LENGTH),
                                          algorithm=hashes.SHA256())
        transaction = Transaction(content=coin_id_and_public_key,
                                  type=TransactionType.transfer,
                                  currency=self.coin_name,
                                  party_from=self.name,
                                  party_to=to_name,
                                  amount=1,
                                  signature=signature)
        self.pool -= 1
        return transaction

    def __repr__(self) -> str:
        return repr(f"CoinMaker(name={self.name}, coin_name={self.coin_name}, pool={self.pool})")


class Person:
    def __init__(self, name: str) -> None:
        self.name = name
        self.private_key, self.public_key = generate_keys()
        self.balance: Dict[str, float] = defaultdict(float)

    def get_public_key(self) -> rsa.RSAPublicKey:
        return self.public_key

    def __repr__(self) -> str:
        return repr(f"Person(name={self.name}, balance: {self.balance})")


class Environment:
    def __init__(self, coin_maker: CoinMaker) -> None:
        self.alice = Person(name="Alice")
        self.bob = Person(name="Bob")
        self.coin_maker = coin_maker
        self.public_keys: Dict[str, rsa.RSAPublicKey] = {}

    def _get_public_keys(self) -> None:
        for party in [self.alice, self.bob, self.coin_maker]:
            self.public_keys[party.name] = party.get_public_key()

    def run(self) -> None:
        self._get_public_keys()
        # coin maker mints coin
        transaction0 = self.coin_maker.mint_single_coin()
        # Alice (or someone) verifies the mint
        self.public_keys[self.coin_maker.name].verify(transaction0.signature, transaction0.content,
                                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                            salt_length=padding.PSS.MAX_LENGTH),
                                                hashes.SHA256())
        # coin maker wants to give the coin to Alice
        transaction1 = self.coin_maker.send_single_coin_to(to_name=self.alice.name, to_public_key=self.alice.public_key,
                                                           coin_id=transaction0.content)
        # Alice (or someone) verifies
        self.public_keys[self.coin_maker.name].verify(transaction1.signature, transaction1.content,
                                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                            salt_length=padding.PSS.MAX_LENGTH),
                                                hashes.SHA256())
        self.alice.balance[transaction1.currency] += transaction1.amount
        print(f"{self.alice.name} verified successfully that {self.coin_maker.name}"
              f" gave her 1 {transaction1.currency} coin")
