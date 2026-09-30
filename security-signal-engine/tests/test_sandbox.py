from src.runtime.sandbox import DockerSandbox, SandboxError


def test_sandbox_fails_closed_without_docker(monkeypatch):
    monkeypatch.setattr("src.runtime.sandbox.shutil.which", lambda name: None)

    try:
        DockerSandbox().check_available()
    except SandboxError as error:
        assert "Docker CLI was not found" in str(error)
    else:
        raise AssertionError("sandbox should fail when Docker is unavailable")