"""
A simple setup for crypto-based transactions without decentralization
For a single coin (1 type of coin, and amount=1)
"""
from __future__ import annotations

from abc import ABCMeta, abstractmethod

from typing import Tuple, Optional, Dict, Set, List

from dataclasses import dataclass

import binascii
import os

from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding


def generate_keys(key_size: int = 512) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=crypto_default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


class Party(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, name: str):
        self.name = name
        self.pool: Set[Coin] = set()
        self._private_key, self.public_key = generate_keys()

    @property
    @abstractmethod
    def balance(self) -> float:
        pass

    @abstractmethod
    def get_public_key(self) -> rsa.RSAPublicKey:
        pass

    @abstractmethod
    def send_single_coin_to(self, to_party: Party, to_public_key: rsa.RSAPublicKey, coin: Coin) -> Transaction:
        pass


class TransactionType(Enum):
    mint = "mint"
    transfer = "transfer"


@dataclass(frozen=True)
class Coin:
    cid: bytes
    currency: str


@dataclass(frozen=True)
class Transaction:
    """
    Represents a transaction of 1 coin.\n

    type: Enum that indicates the action - mint, or transfer\n
    content: either the coin id or the coin id and the public key of party_to\n
    currency: the name of the currency in the transaction\n
    signature: cryptographic signature of the content (signed by party_from)
    """
    type: TransactionType
    coin: Coin
    content: bytes
    currency: str
    party_from: Party
    signature: bytes
    party_to: Optional[Party] = None


class CoinMaker(Party):
    def __init__(self, coin_name: str, name: str) -> None:
        super().__init__(name=name)
        self.coin_name = coin_name
        self.number_of_bytes = 3

    @property
    def balance(self) -> float:
        return len(self.pool)

    def get_public_key(self) -> rsa.RSAPublicKey:
        return self.public_key

    def mint_single_coin(self) -> Transaction:
        coin = Coin(binascii.b2a_hex(os.urandom(self.number_of_bytes)), self.coin_name)   # generate random coin id
        signature = self._private_key.sign(coin.cid,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                      salt_length=padding.PSS.MAX_LENGTH),
                                          algorithm=hashes.SHA256())
        transaction = Transaction(content=coin.cid,
                                  coin=coin,
                                  type=TransactionType.mint,
                                  currency=self.coin_name,
                                  party_from=self,
                                  signature=signature)
        self.pool.add(coin)
        return transaction

    def send_single_coin_to(self, to_party: Party, to_public_key: rsa.RSAPublicKey, coin: Coin) -> Transaction:
        coin_id_and_public_key = bytearray(coin.cid)
        coin_id_and_public_key.extend(to_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        signature = self._private_key.sign(coin_id_and_public_key,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                      salt_length=padding.PSS.MAX_LENGTH),
                                          algorithm=hashes.SHA256())
        transaction = Transaction(content=coin_id_and_public_key,
                                  coin=coin,
                                  type=TransactionType.transfer,
                                  currency=self.coin_name,
                                  party_from=self,
                                  party_to=to_party,
                                  signature=signature)
        self.pool.remove(coin)
        return transaction

    def __repr__(self) -> str:
        return repr(f"CoinMaker(name={self.name}, coin_name={self.coin_name}, balance={self.balance})")


class Person(Party):
    def __init__(self, name: str) -> None:
        super().__init__(name=name)

    @property
    def balance(self) -> float:
        return len(self.pool)

    def _does_have_coin(self, coin: Coin) -> bool:
        return coin in self.pool

    def send_single_coin_to(self, to_party: Party, to_public_key: rsa.RSAPublicKey, coin: Coin) -> Transaction:
        if not self._does_have_coin(coin):
            raise RuntimeError(f"{self.name} does not have coin {coin}")
        coin_id_and_public_key = bytearray(coin.cid)
        coin_id_and_public_key.extend(to_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        signature = self._private_key.sign(coin_id_and_public_key,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                      salt_length=padding.PSS.MAX_LENGTH),
                                          algorithm=hashes.SHA256())
        transaction = Transaction(content=coin_id_and_public_key,
                                  coin=coin,
                                  type=TransactionType.transfer,
                                  currency=coin.currency,
                                  party_from=self,
                                  party_to=to_party,
                                  signature=signature)
        self.pool.remove(coin)
        return transaction

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
        self.ledger: List[Transaction] = []

    def _get_public_keys(self) -> None:
        for party in [self.alice, self.bob, self.coin_maker]:
            self.public_keys[party.name] = party.get_public_key()

    def validate(self, this_transaction: Transaction) -> None:
        this_transaction.party_from.public_key.verify(self.ledger[-1].signature, this_transaction.content,
                                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                            salt_length=padding.PSS.MAX_LENGTH),
                                                hashes.SHA256())
        for i, transaction in enumerate(reversed(self.ledger[:-1])):
            if (transaction.type == TransactionType.mint) or (transaction.party_to is None):
                return None
            # Follow chain of ownership:
            # check that the public_key of the from_party matches the signature of the sending party
            # in the previous transaction.
            transaction.party_from.public_key.verify(self.ledger[i + 1].signature, transaction.content,
                                                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                   salt_length=padding.PSS.MAX_LENGTH),
                                                       hashes.SHA256())



    def run(self) -> None:
        self._get_public_keys()
        # coin maker mints coin
        transaction0 = self.coin_maker.mint_single_coin()
        self.ledger.append(transaction0)
        # Alice (or someone) verifies the mint
        transaction0.party_from.public_key.verify(transaction0.signature, transaction0.content,
                                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                            salt_length=padding.PSS.MAX_LENGTH),
                                                hashes.SHA256())
        # coin maker wants to give the coin to Alice
        transaction1 = self.coin_maker.send_single_coin_to(to_party=self.alice, to_public_key=self.alice.public_key,
                                                           coin=transaction0.coin)
        self.ledger.append(transaction1)
        # Alice (or someone) verifies
        self.validate(transaction1)
        self.alice.pool.add(transaction1.coin)
        print(f"{self.alice.name} verified successfully that {self.coin_maker.name}"
              f" gave her 1 {transaction1.currency} coin")

        # Alice sends the same coin to Bob
        transaction2 = self.alice.send_single_coin_to(to_party=self.bob, to_public_key=self.bob.public_key,
                                       coin=transaction1.coin)
        self.ledger.append(transaction2)
        # Bob (or anyone else) verifies that Alice can send the coin,
        # matching the public key that was used to give the coin to her with the private key
        # she used to sign the sending transaction
        # transaction1.party_to.public_key.verify(transaction2.signature, transaction2.content,
        #                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
        #                                                      salt_length=padding.PSS.MAX_LENGTH),
        #                                          hashes.SHA256())
        self.validate(transaction2)
        self.bob.pool.add(transaction2.coin)
        # If bob tries to verify that coin_maker sent the coin, it will fail
        try:
            self.public_keys[self.coin_maker.name].verify(transaction2.signature, transaction2.content,
                                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                 salt_length=padding.PSS.MAX_LENGTH),
                                                     hashes.SHA256())
        except InvalidSignature:
            print(f"{self.coin_maker.name} couldn't have sent this coin to {transaction2.party_to.name}!")
