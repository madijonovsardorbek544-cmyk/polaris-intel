from src.config import load_env


def test_env_loading_reads_local_dotenv_without_overriding(tmp_path, monkeypatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MAX_ITEMS=123\nLOG_LEVEL=DEBUG\n")
    monkeypatch.delenv("MAX_ITEMS", raising=False)
    monkeypatch.setenv("LOG_LEVEL", "WARNING")

    load_env(env_file)

    assert __import__("os").environ["MAX_ITEMS"] == "123"
    assert __import__("os").environ["LOG_LEVEL"] == "WARNING"
