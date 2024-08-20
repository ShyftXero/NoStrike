import pytest
from pathlib import Path
import subprocess
from unittest.mock import patch, mock_open
from nostrike import read_nostrike_file, is_valid_ip, is_valid_cidr, resolve_hostname, create_iptables_rules, execute_command, check_permissions

@pytest.fixture
def mock_nostrike_file():
    return """
    192.168.1.100 # Block this IP
    10.0.0.0/24 # Block this subnet
    evil.com # Block this domain
    # This is a comment
    """

def test_read_nostrike_file(mock_nostrike_file):
    with patch("builtins.open", mock_open(read_data=mock_nostrike_file)):
        result = read_nostrike_file("dummy_path")
    assert result == ["192.168.1.100", "10.0.0.0/24", "evil.com"]

def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1") == True
    assert is_valid_ip("256.0.0.1") == False
    assert is_valid_ip("example.com") == False
    assert is_valid_ip("-1.-1.-1.-1") == False
    assert is_valid_ip("777.777.777.777") == False

def test_is_valid_cidr():
    assert is_valid_cidr("192.168.1.0/24") == True
    assert is_valid_cidr("192.168.1.1") == False
    assert is_valid_cidr("192.168.1.0/33") == False
    assert is_valid_cidr("256.0.0.0/24") == False
    assert is_valid_cidr("192.168.1.0/0") == True
    assert is_valid_cidr("10.0.0.0/8") == True
    assert is_valid_cidr("invalid_cidr") == False

@pytest.mark.parametrize("hostname, expected", [
    ("example.com", ["93.184.216.34"]),
    ("nonexistent.example.com", [])
])
def test_resolve_hostname(hostname, expected):
    with patch("dns.resolver.resolve") as mock_resolve:
        mock_resolve.return_value = [type('obj', (object,), {'address': ip}) for ip in expected]
        result = resolve_hostname(hostname)
    assert result == expected

def test_create_iptables_rules_ip():
    rules = create_iptables_rules("192.168.1.100")
    expected_rules = [
        "iptables -A INPUT -s 192.168.1.100 -j DROP",
        "iptables -A OUTPUT -d 192.168.1.100 -j DROP"
    ]
    assert rules == expected_rules

def test_create_iptables_rules_cidr():
    rules = create_iptables_rules("10.0.0.0/24")
    expected_rules = [
        "iptables -A INPUT -s 10.0.0.0/24 -j DROP",
        "iptables -A OUTPUT -d 10.0.0.0/24 -j DROP"
    ]
    assert rules == expected_rules

def test_create_iptables_rules_hostname():
    with patch("nostrike.resolve_hostname") as mock_resolve:
        mock_resolve.return_value = ["93.184.216.34"]
        rules = create_iptables_rules("example.com")
    expected_rules = [
        "iptables -A INPUT -s 93.184.216.34 -j DROP",
        "iptables -A OUTPUT -d 93.184.216.34 -j DROP"
    ]
    assert rules == expected_rules

def test_execute_command():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Command executed successfully"
        mock_run.return_value.stderr = ""
        rc, stdout, stderr = execute_command("test command")
    assert rc == 0
    assert stdout == "Command executed successfully"
    assert stderr == ""

def test_execute_command_dry_run():
    with patch("builtins.print") as mock_print:
        rc, stdout, stderr = execute_command("test command", dry_run=True)
    mock_print.assert_called_once_with("[Dry run] Would execute: test command")
    assert rc == 0
    assert stdout == ""
    assert stderr == ""

@patch("subprocess.run")
@patch("sys.platform", "linux")
def test_check_permissions_linux(mock_run):
    mock_run.side_effect = [
        subprocess.CalledProcessError(1, "iptables -L"),
        subprocess.CompletedProcess("sudo -v", 0)
    ]
    result = check_permissions()
    assert result == "sudo"

@patch("subprocess.run")
@patch("sys.platform", "win32")
def test_check_permissions_windows(mock_run):
    mock_run.return_value = subprocess.CompletedProcess("iptables -L", 0)
    result = check_permissions()
    assert result == ""