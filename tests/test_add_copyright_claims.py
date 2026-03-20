from scripts import add_copyright_claims as acc


def test_main_logs_debug_when_symlink_check_fails(monkeypatch, tmp_path):
    target = tmp_path / "sample.txt"
    target.write_text("hej", encoding="utf-8")
    debug_calls = []

    monkeypatch.setattr(acc, "is_dev_mode_enabled", lambda _value: True)
    monkeypatch.setattr(acc.os, "walk", lambda _root: [(str(tmp_path), [], [target.name])])

    def fake_is_symlink(self):
        if self == target:
            raise OSError("låst")
        return False

    monkeypatch.setattr(acc.Path, "is_symlink", fake_is_symlink)
    monkeypatch.setattr(
        acc.logger,
        "debug",
        lambda message, *args, **kwargs: debug_calls.append(message % args),
    )

    acc.main()

    assert len(debug_calls) == 1
    assert str(target) in debug_calls[0]


def test_main_logs_warning_when_read_text_fails(monkeypatch, tmp_path):
    target = tmp_path / "sample.txt"
    target.write_text("hej", encoding="utf-8")
    warning_calls = []
    original_read_text = acc.Path.read_text

    monkeypatch.setattr(acc, "is_dev_mode_enabled", lambda _value: True)
    monkeypatch.setattr(acc.os, "walk", lambda _root: [(str(tmp_path), [], [target.name])])
    monkeypatch.setattr(acc, "is_binary", lambda _path: False)

    def fake_read_text(self, *args, **kwargs):
        if self == target:
            raise OSError("låst")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(acc.Path, "read_text", fake_read_text)
    monkeypatch.setattr(
        acc.logger,
        "warning",
        lambda message, *args, **kwargs: warning_calls.append(message % args),
    )

    acc.main()

    assert len(warning_calls) == 1
    assert str(target) in warning_calls[0]


# Copyright (c) Liam Suorsa and Mika Suorsa
