from __future__ import annotations
import hashlib
from hashlib import sha256
from typing import Optional, Union, Generic, TypeVar


"""
Blockchain as a linked list with hash pointers
"""

T = TypeVar("T")


def display_x_characters_of_string(string: str, num_characters: int = 7) -> str:
    start = string[0:num_characters]
    end = string[-num_characters:]
    return start + "..." + end


class Block(Generic[T]):
    def __init__(self, data: T) -> None:
        self.data = data
        self.hash: Optional[hashlib._Hash] = None
        self.next_hash: Optional[hashlib._Hash] = None
        self.next: Optional[Block] = None
        self.data_hash: Optional[hashlib._Hash] = None
        self.previous: Optional[Block] = None

    def __repr__(self) -> str:
        return repr(f"Block(data: {self.data},"
                    f" data_hash: {display_x_characters_of_string(self.data_hash.hexdigest()) if self.data_hash else 'None'},"
                    f" hash: {display_x_characters_of_string(self.hash.hexdigest()) if self.hash else 'None'},"
                    f" next_hash: {display_x_characters_of_string(self.next_hash.hexdigest()) if self.next_hash else 'None'})")


class Blockchain:
    def __init__(self, head: Optional[Block] = None) -> None:
        self.head = head
        self.genesis_block = head   # the last item in the list is the first block in the chain

    @staticmethod
    def _hash_block_data(block: Block) -> hashlib._Hash:
        if isinstance(block.data, (int, float)):
            block.data_hash = sha256(bytes(block.data))
        elif isinstance(block.data, str):
            block.data_hash = sha256(bytes(block.data.encode("utf-8")))
        elif isinstance(block.data, bytes):
            block.data_hash = sha256(block.data)
        else:
            raise TypeError(f"Data type {type(block.data)} not supported")
        return block.data_hash

    def _hash_block(self, block: Block) -> hashlib._Hash:
        if block.data and not block.next_hash:
            return self._hash_block_data(block)
        elif block.data and block.next_hash:
            self._hash_block_data(block)
            data_and_hash = str(str(block.data) + block.next_hash.hexdigest()) if block.next_hash else str(block.data_hash.hexdigest())
            return sha256(bytes(data_and_hash.encode("utf-8")))
        else:
            raise RuntimeError("No data in block")

    def back_propagate_changes(self) -> None:
        if self.genesis_block:
            self.genesis_block.hash = self._hash_block(self.genesis_block)
            current = self.genesis_block
            while current.previous:
                current.previous.next_hash = self._hash_block(current)
                current.previous.hash = self._hash_block(current.previous)
                current = current.previous
        else:
            raise RuntimeError("No blocks in the chain")

    def add_block(self, new_block: Block) -> None:
        """
        Adding block to the beginning of the list!
        """
        if self.head:
            new_block.next = self.head
            new_block.next_hash = self.head.hash
            self.head.previous = new_block
            self.head = new_block
            self.head.hash = self._hash_block(self.head)
        else:
            self.head = new_block
            self.genesis_block = new_block      # a one-time assignment!
            self.head.hash = self._hash_block_data(self.head)

    @property
    def head_pointer(self) -> hashlib._Hash:
        if self.head:
            return display_x_characters_of_string(self._hash_block(self.head).hexdigest())
        raise RuntimeError("No blocks in chain")

    def get_block_at_position(self, position: int) -> Block:
        if self.head:
            if position == 1:
                return self.head
            else:
                pos = self.head
                for _ in range(1, position):
                    if pos.next:
                        pos = pos.next
                    else:
                        raise ValueError("No such position in chain")
                return pos
        else:
            raise RuntimeError("No blocks in chain")

    def change_block(self, position: int, new_data: Union[str, int, float]) -> None:
        block_to_change = self.get_block_at_position(position)
        block_to_change.data = new_data

    def __repr__(self) -> str:
        ans = ""
        if self.head:
            ans += str(self.head.data) +\
                   " data_hash: " + str(display_x_characters_of_string(self.head.data_hash.hexdigest()) if self.head.data_hash else "None") +\
                   " hash: " + str(display_x_characters_of_string(self.head.hash.hexdigest()) if self.head.hash else "None") +\
                   " next_hash: " + str(display_x_characters_of_string(self.head.next_hash.hexdigest()) if self.head.next_hash else "None") +\
                   "\n"
            current = self.head
            while current.next:
                current = current.next
                ans += str(current.data) +\
                       " data_hash: " + str(display_x_characters_of_string(current.data_hash.hexdigest()) if current.data_hash else "None") +\
                       " hash: " + str(display_x_characters_of_string(current.hash.hexdigest()) if current.hash else "None") +\
                       " next_hash: " + str(display_x_characters_of_string(current.next_hash.hexdigest()) if current.next_hash else "None") +\
                       "\n"
        return ans
