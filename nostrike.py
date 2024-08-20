import typer
import ipaddress
import json
import logging
import subprocess
import sys
from typing import List, Dict, Tuple
from pathlib import Path
from mpire import WorkerPool
import dns.resolver
import multiprocessing
import shlex
import random
import pyfiglet



app = typer.Typer()

# ASCII_LOGO = """
#  _   _       _____ _        _ _        
# | \ | |     /  ___| |      (_) |       
# |  \| | ___ \ `--.| |_ _ __ _| | _____ 
# | . ` |/ _ \ `--. \ __| '__| | |/ / _ \\
# | |\  | (_) /\__/ / |_| |  | |   <  __/
# \_| \_/\___/\____/ \__|_|  |_|_|\_\___|
# """

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def show_logo():
    fonts = [
        "3-d", "3x5", "5lineoblique", "slant",
        "5lineoblique","alphabet", "banner3-D",
        "doh", "isometric1", "letters",
        "alligator", "bubble"
    ]

    f = pyfiglet.figlet_format("NoStrike", font = random.choice(fonts))
    print('\nshyft presents...')
    print(f)
    print('Prevent network traffic to hosts in ~/nostrike.txt')
    print('='*25)
    print()


def read_nostrike_file(file_path: str) -> List[str]:
    """Read and return the contents of the nostrike file, ignoring comments."""
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()

        targets = []
        for line in lines:
            parts = line.split('#', 1)
            target = parts[0].strip()
            if target:
                targets.append(target)

        return targets
    except FileNotFoundError:
        logging.error(f"Error: File {file_path} not found.")
        raise typer.Abort()
    except IOError as e:
        logging.error(f"Error reading file: {e}")
        raise typer.Abort()

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_cidr(cidr: str) -> bool:
    try:
        # Check if the string contains a '/'
        if '/' not in cidr:
            return False
        
        # Split the CIDR notation into network and prefix
        network, prefix = cidr.split('/')
        
        # Validate the network part as an IP address
        ipaddress.ip_address(network)
        
        # Validate the prefix as an integer between 0 and 32
        prefix_int = int(prefix)
        if prefix_int < 0 or prefix_int > 32:
            return False
        
        # If all checks pass, it's a valid CIDR
        return True
    except ValueError:
        return False

def resolve_hostname(hostname: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        return [rdata.address for rdata in answers]
    except dns.resolver.NXDOMAIN:
        logging.warning(f"Unable to resolve hostname {hostname}")
        return []

def create_iptables_rules(target: str) -> List[str]:
    rules = []
    if is_valid_ip(target) or is_valid_cidr(target):
        rules.extend([
            f"iptables -A INPUT -s {target} -j DROP",
            f"iptables -A OUTPUT -d {target} -j DROP"
        ])
    else:
        ips = resolve_hostname(target)
        for ip in ips:
            rules.extend([
                f"iptables -A INPUT -s {ip} -j DROP",
                f"iptables -A OUTPUT -d {ip} -j DROP"
            ])
    return rules

def execute_command(command: str, dry_run: bool = False) -> Tuple[int, str, str]:
    if dry_run:
        print(f"[Dry run] Would execute: {command}")
        return 0, "", ""
    
    try:
        result = subprocess.run(shlex.split(command), check=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr

def check_permissions():
    rc, _, _ = execute_command("iptables -L")
    if rc != 0:
        logging.error("Insufficient permissions to run iptables commands.")
        if sys.platform.startswith('linux'):
            logging.info("Attempting to elevate privileges...")
            try:
                subprocess.run(["sudo", "-v"], check=True)
                return "sudo"
            except subprocess.CalledProcessError:
                logging.error("Failed to elevate privileges. Please run the script with sudo.")
                raise typer.Abort()
    return ""

@app.command()
def block(
    file: Path = typer.Option("~/nostrike.txt", help="Path to the nostrike file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print commands without executing them")
):
    """Configure the firewall based on the contents of the nostrike file."""
    show_logo()
    file = Path(file).expanduser()
    targets = read_nostrike_file(str(file))
    
    sudo_prefix = check_permissions()
    
    with WorkerPool(n_jobs=multiprocessing.cpu_count()) as pool:
        all_rules = pool.map(create_iptables_rules, targets)
    
    rules_to_apply = [rule for sublist in all_rules for rule in sublist]
    
    for rule in rules_to_apply:
        command = f"{sudo_prefix} {rule}" if sudo_prefix else rule
        rc, stdout, stderr = execute_command(command, dry_run)
        if rc != 0:
            logging.error(f"Error applying rule: {rule}")
            logging.error(f"Error message: {stderr}")
        elif not dry_run:
            logging.info(f"Applied rule: {rule}")
    
    if not dry_run:
        logging.info("Firewall configured successfully.")
    else:
        logging.info("Dry run completed. Above are the commands that would have been executed.")

@app.command()
def reset(dry_run: bool = typer.Option(False, "--dry-run", help="Print commands without executing them")):
    """Reset the firewall by flushing all iptables rules."""
    show_logo()
    sudo_prefix = check_permissions()
    
    commands = [
        "iptables -F",  # Flush all rules
        "iptables -X",  # Delete all user-defined chains
        "iptables -Z",  # Zero all packet and byte counters
        "iptables -P INPUT ACCEPT",  # Set default policies to ACCEPT
        "iptables -P FORWARD ACCEPT",
        "iptables -P OUTPUT ACCEPT"
    ]
    
    for cmd in commands:
        command = f"{sudo_prefix} {cmd}" if sudo_prefix else cmd
        rc, stdout, stderr = execute_command(command, dry_run)
        if rc != 0:
            logging.error(f"Error executing command: {cmd}")
            logging.error(f"Error message: {stderr}")
        elif not dry_run:
            logging.info(f"Executed command: {cmd}")
    
    if not dry_run:
        logging.info("Firewall rules reset successfully.")
    else:
        logging.info("Dry run completed. Above are the commands that would have been executed.")

@app.command()
def save(file_path: str = typer.Option("~/firewall_backup.json", help="Path to save the current firewall configuration")):
    """Save the current firewall configuration to a file."""
    show_logo()
    file_path = Path(file_path).expanduser()
    sudo_prefix = check_permissions()
    
    command = f"{sudo_prefix} iptables-save" if sudo_prefix else "iptables-save"
    rc, stdout, stderr = execute_command(command)
    
    if rc == 0:
        try:
            with open(file_path, 'w') as f:
                f.write(stdout)
            logging.info(f"Current firewall configuration saved to {file_path}")
        except IOError as e:
            logging.error(f"Error writing to file: {e}")
    else:
        logging.error(f"Error saving firewall configuration: {stderr}")

@app.command()
def restore(
    file_path: str = typer.Option("~/firewall_backup.json", help="Path to the firewall configuration backup file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print commands without executing them")
):
    """Restore a previously saved firewall configuration."""
    show_logo()
    file_path = Path(file_path).expanduser()
    sudo_prefix = check_permissions()
    
    try:
        with open(file_path, 'r') as f:
            config = f.read()
        
        if dry_run:
            print(f"[Dry run] Would restore the following configuration:\n{config}")
        else:
            command = f"{sudo_prefix} iptables-restore" if sudo_prefix else "iptables-restore"
            rc, stdout, stderr = execute_command(command, input=config)
            
            if rc == 0:
                logging.info("Firewall configuration restored successfully.")
            else:
                logging.error(f"Error restoring firewall configuration: {stderr}")
    except FileNotFoundError:
        logging.error(f"Error: Backup file {file_path} not found.")
        raise typer.Abort()
    except IOError as e:
        logging.error(f"Error reading file: {e}")
        raise typer.Abort()

if __name__ == "__main__":
    app()
