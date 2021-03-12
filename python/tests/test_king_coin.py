import pytest

from ..king_coin import CoinMaker, Environment


@pytest.fixture
def coin_maker() -> CoinMaker:
    return CoinMaker(coin_name="KingCoin", owner="Johnoshi")


@pytest.fixture
def environment(coin_maker) -> Environment:
    return Environment(coin_maker)


def test_simple_env_run(environment, capsys) -> None:
    environment.run()
    captured = capsys.readouterr()
    assert captured.out.strip() == "Alice verified successfully that Johnoshi gave her 1 KingCoin coin"
