import pytest

from python.linked_list_hash import Blockchain, Block


@pytest.fixture
def blockchain() -> Blockchain:
    blockchain = Blockchain()
    blockchain.add_block(Block("oren"))
    blockchain.add_block(Block(2))
    blockchain.add_block(Block(3))
    return blockchain


def test_temper_with_data(blockchain) -> None:
    original_head_pointer = blockchain.head_pointer
    blockchain.change_block(2, "new_data")
    blockchain.back_propagate_changes()
    new_pointer = blockchain.head_pointer
    assert new_pointer != original_head_pointer


def test_temper_with_genesis_block(blockchain) -> None:
    original_head_pointer = blockchain.head_pointer
    blockchain.change_block(3, "new_data")
    blockchain.back_propagate_changes()
    new_pointer = blockchain.head_pointer
    assert new_pointer != original_head_pointer


def test_normal_flow(blockchain) -> None:
    original_head_pointer = blockchain.head_pointer
    blockchain.back_propagate_changes()
    new_pointer = blockchain.head_pointer
    assert original_head_pointer == new_pointer


def test_normal_flow_backpropagate_twice(blockchain) -> None:
    original_head_pointer = blockchain.head_pointer
    blockchain.back_propagate_changes()
    blockchain.back_propagate_changes()
    new_pointer = blockchain.head_pointer
    assert original_head_pointer == new_pointer
