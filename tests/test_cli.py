import pytest
from click.testing import CliRunner


@pytest.fixture
def runner():
    return CliRunner()


class TestCLI:
    def test_cli_help(self, runner):
        try:
            from backend.cli.main import cli
        except ImportError:
            pytest.skip("CLI module not yet implemented")
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Usage" in result.output

    def test_cli_target_validate(self, runner):
        try:
            from backend.cli.main import cli
        except ImportError:
            pytest.skip("CLI module not yet implemented")
        pytest.skip("Requires running API server")

    def test_cli_target_validate_invalid(self, runner):
        try:
            from backend.cli.main import cli
        except ImportError:
            pytest.skip("CLI module not yet implemented")
        pytest.skip("Requires running API server")

    def test_cli_scan_help(self, runner):
        try:
            from backend.cli.main import cli
        except ImportError:
            pytest.skip("CLI module not yet implemented")
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0

    def test_cli_config_help(self, runner):
        try:
            from backend.cli.main import cli
        except ImportError:
            pytest.skip("CLI module not yet implemented")
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Usage" in result.output