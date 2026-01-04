#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Squid Proxy HTTPS Whitelist Setup
Installs and configures Squid to whitelist a single domain.
Supports SSL Bump peek-and-splice or peek-and-bump for HTTPS inspection.
"""
from __future__ import print_function

import argparse
import os
import shutil
import subprocess
import sys
import time

# ------------------------------------------------------------------------------
# ANSI color codes
# ------------------------------------------------------------------------------
C_RESET = "\033[0m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"


# ------------------------------------------------------------------------------
# Output helpers
# ------------------------------------------------------------------------------
def banner():
    """Print ASCII banner."""
    art = r"""
    {cyan}{bold}
     ___  ___  _   _ ___ ___    ___ ___ _____  ___   _____
    / __|/ _ \| | | |_ _|   \  / __| __|_   _|/ | | | | _ \
    \__ \ (_) | |_| || || |) | \__ \ _|  | | | |_| |_| |  _/
    |___/\__\_\\___/|___|___/  |___/___| |_|  \___/___/|_|

    {reset}{dim}[ HTTPS WHITELIST PROXY CONFIGURATOR ]{reset}
    """.format(cyan=C_CYAN, bold=C_BOLD, reset=C_RESET, dim=C_DIM)
    print(art)


def info(msg):
    """Print info message."""
    print("{cyan}[*]{reset} {msg}".format(cyan=C_CYAN, reset=C_RESET, msg=msg))


def success(msg):
    """Print success message."""
    print("{green}[+]{reset} {msg}".format(green=C_GREEN, reset=C_RESET, msg=msg))


def error(msg):
    """Print error message."""
    print("{red}[-]{reset} {msg}".format(red=C_RED, reset=C_RESET, msg=msg))


def warn(msg):
    """Print warning message."""
    print("{yellow}[!]{reset} {msg}".format(yellow=C_YELLOW, reset=C_RESET, msg=msg))


def action(msg):
    """Print action message."""
    print("{cyan}[>]{reset} {msg}".format(cyan=C_CYAN, reset=C_RESET, msg=msg))


def step_delay():
    """Small delay for dramatic effect."""
    time.sleep(0.3)


# ------------------------------------------------------------------------------
# System checks
# ------------------------------------------------------------------------------
def check_root():
    """Check if running as root."""
    info("Checking privileges...")
    step_delay()
    if os.geteuid() != 0:
        error("ACCESS DENIED: Must run as root")
        error("Try: sudo python {0}".format(sys.argv[0]))
        sys.exit(1)
    success("Root access confirmed")


def check_squid_installed():
    """Check if Squid is already installed."""
    info("Scanning for existing Squid installation...")
    step_delay()
    ret = subprocess.call(
        ["which", "squid"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return ret == 0


def check_squid_ssl_support():
    """Check if installed Squid has SSL support."""
    info("Checking Squid SSL support...")
    step_delay()
    try:
        proc = subprocess.Popen(
            ["squid", "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, _ = proc.communicate()
        output = stdout.decode("utf-8", errors="replace")
        return "--with-openssl" in output or "--enable-ssl" in output
    except Exception:
        return False


# ------------------------------------------------------------------------------
# Installation
# ------------------------------------------------------------------------------
def install_squid():
    """Install Squid proxy via apt-get."""
    package = "squid-openssl"

    action("Updating package lists...")
    step_delay()
    ret = subprocess.call(["apt-get", "update", "-qq"])
    if ret != 0:
        error("Failed to update package lists")
        sys.exit(1)
    success("Package lists updated")

    action("Installing {0} package...".format(package))
    step_delay()
    ret = subprocess.call(["apt-get", "install", "-y", "-qq", package])
    if ret != 0:
        error("Failed to install {0}".format(package))
        warn("squid-openssl may not be available in your repos")
        warn("Try: apt-get install squid-openssl")
        sys.exit(1)
    success("{0} package installed".format(package))


# ------------------------------------------------------------------------------
# Certificate management
# ------------------------------------------------------------------------------
def get_cert_dir(script_dir):
    """Get certificate directory, create if needed."""
    cert_dir = os.path.join(script_dir, "certs")
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)
    return cert_dir


def check_existing_certs(cert_dir):
    """Check if CA certificate and key already exist."""
    cert_path = os.path.join(cert_dir, "squid-ca-cert.pem")
    key_path = os.path.join(cert_dir, "squid-ca-key.pem")
    return os.path.exists(cert_path) and os.path.exists(key_path)


def generate_ca_cert(cert_dir):
    """Generate self-signed CA certificate using openssl."""
    cert_path = os.path.join(cert_dir, "squid-ca-cert.pem")
    key_path = os.path.join(cert_dir, "squid-ca-key.pem")

    # Check if certs already exist
    if check_existing_certs(cert_dir):
        info("Existing CA certificate found")
        success("Reusing CA from {0}".format(cert_dir))
        return cert_path, key_path

    action("Generating self-signed CA certificate...")
    step_delay()

    cmd = [
        "openssl", "req",
        "-new", "-newkey", "rsa:2048",
        "-days", "365",
        "-nodes", "-x509",
        "-subj", "/CN=Squid Proxy CA/O=Squid Whitelist Proxy",
        "-keyout", key_path,
        "-out", cert_path
    ]

    ret = subprocess.call(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ret != 0:
        error("Failed to generate CA certificate")
        sys.exit(1)

    # Set proper permissions
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)

    success("CA certificate generated")
    info("  Certificate: {0}".format(cert_path))
    info("  Private key: {0}".format(key_path))

    return cert_path, key_path


def copy_certs_to_squid(cert_path, key_path):
    """Copy certificates to Squid directory."""
    squid_cert_dir = "/etc/squid/certs"
    if not os.path.exists(squid_cert_dir):
        os.makedirs(squid_cert_dir)

    dest_cert = os.path.join(squid_cert_dir, "squid-ca-cert.pem")
    dest_key = os.path.join(squid_cert_dir, "squid-ca-key.pem")

    action("Copying certificates to Squid directory...")
    step_delay()

    shutil.copy2(cert_path, dest_cert)
    shutil.copy2(key_path, dest_key)

    # Ensure Squid can read them
    os.chmod(dest_cert, 0o644)
    os.chmod(dest_key, 0o600)

    # Change ownership to proxy user
    try:
        import pwd
        proxy_uid = pwd.getpwnam("proxy").pw_uid
        proxy_gid = pwd.getpwnam("proxy").pw_gid
        os.chown(dest_cert, proxy_uid, proxy_gid)
        os.chown(dest_key, proxy_uid, proxy_gid)
        os.chown(squid_cert_dir, proxy_uid, proxy_gid)
    except (KeyError, OSError):
        warn("Could not set ownership to proxy user")

    success("Certificates copied to {0}".format(squid_cert_dir))
    return dest_cert, dest_key


def find_ssl_crtd():
    """Find the SSL certificate generator helper binary."""
    # Known paths for ssl_crtd/security_file_certgen
    known_paths = [
        "/usr/lib/squid/security_file_certgen",
        "/usr/lib64/squid/security_file_certgen",
        "/usr/libexec/squid/security_file_certgen",
        "/usr/lib/squid/ssl_crtd",
        "/usr/lib64/squid/ssl_crtd",
        "/usr/lib/squid3/security_file_certgen",
        "/usr/lib/squid3/ssl_crtd",
        "/usr/local/squid/libexec/security_file_certgen",
        "/usr/local/libexec/squid/security_file_certgen",
    ]

    # Check known paths first
    for path in known_paths:
        if os.path.exists(path):
            return path

    # Try to find it dynamically
    search_dirs = ["/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/local"]
    search_names = ["security_file_certgen", "ssl_crtd"]

    for search_dir in search_dirs:
        if not os.path.exists(search_dir):
            continue
        for root, dirs, files in os.walk(search_dir):
            for name in search_names:
                if name in files:
                    return os.path.join(root, name)

    return None


def ensure_ssl_helper_installed():
    """Ensure SSL certificate helper is installed, reinstall squid-openssl if needed."""
    ssl_crtd = find_ssl_crtd()
    if ssl_crtd:
        return ssl_crtd

    warn("SSL helper not found, reinstalling squid-openssl...")
    step_delay()

    # Purge and reinstall to ensure all components are present
    subprocess.call(
        ["apt-get", "remove", "-y", "-qq", "squid", "squid-openssl"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    ret = subprocess.call(["apt-get", "install", "-y", "-qq", "squid-openssl"])
    if ret != 0:
        error("Failed to reinstall squid-openssl")
        return None

    # Try to find it again
    ssl_crtd = find_ssl_crtd()
    if ssl_crtd:
        success("SSL helper installed: {0}".format(ssl_crtd))
    return ssl_crtd


def init_ssl_db():
    """Initialize Squid SSL certificate database."""
    ssl_db_dir = "/var/lib/squid/ssl_db"
    squid_lib_dir = "/var/lib/squid"

    action("Initializing SSL certificate database...")
    step_delay()

    # Ensure parent directory exists
    if not os.path.exists(squid_lib_dir):
        os.makedirs(squid_lib_dir)

    # Remove existing db if present
    if os.path.exists(ssl_db_dir):
        shutil.rmtree(ssl_db_dir)

    # Find or install ssl_crtd helper
    ssl_crtd = ensure_ssl_helper_installed()

    if ssl_crtd is None:
        error("Could not find ssl_crtd/security_file_certgen helper")
        error("SSL Bump may not work correctly")
        warn("Try: dpkg -L squid-openssl | grep -E '(ssl_crtd|security_file_certgen)'")
        return None

    info("Using helper: {0}".format(ssl_crtd))

    # Initialize the database
    cmd = [ssl_crtd, "-c", "-s", ssl_db_dir, "-M", "4MB"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        error("Failed to initialize SSL database")
        if stderr:
            err_msg = stderr.decode("utf-8", errors="replace").strip()
            if err_msg:
                error("  {0}".format(err_msg))
        if stdout:
            out_msg = stdout.decode("utf-8", errors="replace").strip()
            if out_msg:
                info("  {0}".format(out_msg))
        return ssl_crtd  # Still return path for config

    # Set ownership
    try:
        import pwd
        proxy_uid = pwd.getpwnam("proxy").pw_uid
        proxy_gid = pwd.getpwnam("proxy").pw_gid
        for root, dirs, files in os.walk(ssl_db_dir):
            os.chown(root, proxy_uid, proxy_gid)
            for d in dirs:
                os.chown(os.path.join(root, d), proxy_uid, proxy_gid)
            for f in files:
                os.chown(os.path.join(root, f), proxy_uid, proxy_gid)
    except (KeyError, OSError):
        warn("Could not set SSL database ownership")

    success("SSL certificate database initialized")
    return ssl_crtd


# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
def get_template_dir():
    """Get the path to the config templates directory."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, ".config_templates")


def load_template(template_name):
    """Load a template file from the templates directory."""
    template_path = os.path.join(get_template_dir(), template_name)
    with open(template_path, "r") as f:
        return f.read()


def find_ca_trust_sources():
    """Return cafile, capath, and a list of trust source labels."""
    cafile_candidates = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    ]
    capath_candidates = [
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
    ]
    cafile = None
    for path in cafile_candidates:
        if os.path.isfile(path):
            cafile = path
            break
    capath = None
    for path in capath_candidates:
        if os.path.isdir(path):
            capath = path
            break
    sources = []
    if cafile:
        sources.append("cafile={0}".format(cafile))
    if capath:
        sources.append("capath={0}".format(capath))
    return cafile, capath, sources


def build_domain_variants(domain):
    """Normalize domain and return variants for ACLs and display."""
    clean = domain.strip()
    if clean.startswith("*."):
        clean = clean[2:]
    if clean.startswith("."):
        clean = clean[1:]
    apex = clean
    if not apex:
        return domain, "", domain, domain
    wildcard = "." + apex
    domain_acl = "{0} {1}".format(apex, wildcard)
    display = "{0} and *.{0}".format(apex)
    return wildcard, apex, domain_acl, display


def normalize_ssl_bump_mode(mode):
    """Normalize ssl bump mode, keeping backwards-compatible aliases."""
    if mode == "verify":
        return "verify-no-mitm"
    return mode


def generate_config(domain, port, ssl_bump_mode, cert_path, key_path,
                    ssl_crtd_path=None, extra_ssl_ports=None, cafile=None,
                    capath=None):
    """Generate Squid configuration for domain whitelisting."""
    domain, _, domain_acl, domain_display = build_domain_variants(domain)
    if cafile and capath:
        tls_outgoing_options = "tls_outgoing_options cafile={0} capath={1}".format(
            cafile, capath
        )
    elif cafile:
        tls_outgoing_options = "tls_outgoing_options cafile={0}".format(cafile)
    elif capath:
        tls_outgoing_options = "tls_outgoing_options capath={0}".format(capath)
    else:
        tls_outgoing_options = "# tls_outgoing_options cafile=/path/to/ca-bundle (not found)"

    # Build SSL ports list
    ssl_ports_lines = "acl SSL_ports port 443"
    safe_ports_lines = "acl Safe_ports port 80\nacl Safe_ports port 443"
    if extra_ssl_ports:
        for ssl_port in extra_ssl_ports:
            ssl_ports_lines += "\nacl SSL_ports port {0}".format(ssl_port)
            safe_ports_lines += "\nacl Safe_ports port {0}".format(ssl_port)

    # Select template based on ssl_bump_mode
    template_name = "squid_{0}.conf.template".format(ssl_bump_mode)
    template = load_template(template_name)

    # Build substitution values
    values = {
        "domain": domain,
        "domain_acl": domain_acl,
        "domain_display": domain_display,
        "port": port,
        "ssl_ports": ssl_ports_lines,
        "safe_ports": safe_ports_lines,
        "tls_outgoing_options": tls_outgoing_options,
    }

    # Add SSL-specific values for ssl_bump modes
    if ssl_bump_mode != "off":
        values["cert"] = cert_path
        values["key"] = key_path
        values["ssl_crtd"] = ssl_crtd_path or "/usr/lib/squid/security_file_certgen"

    return template.format(**values)


def backup_config():
    """Backup existing Squid configuration (only if backup doesn't exist)."""
    squid_conf = "/etc/squid/squid.conf"
    backup_path = "/etc/squid/squid.conf.bak"

    if os.path.exists(backup_path):
        info("Backup already exists: {0}".format(backup_path))
        return

    if os.path.exists(squid_conf):
        info("Backing up existing configuration...")
        step_delay()
        try:
            shutil.copy2(squid_conf, backup_path)
            success("Backup saved to {0}".format(backup_path))
        except IOError as e:
            warn("Could not backup config: {0}".format(e))


def write_config(config, script_dir):
    """Write configuration to both /etc/squid and script directory."""
    squid_conf = "/etc/squid/squid.conf"
    local_conf = os.path.join(script_dir, "squid.conf")

    # Write to /etc/squid/squid.conf
    action("Writing configuration to {0}...".format(squid_conf))
    step_delay()
    try:
        with open(squid_conf, "w") as f:
            f.write(config)
        success("Configuration written to {0}".format(squid_conf))
    except IOError as e:
        error("Failed to write config: {0}".format(e))
        sys.exit(1)

    # Write local copy
    action("Saving local copy to {0}...".format(local_conf))
    step_delay()
    try:
        with open(local_conf, "w") as f:
            f.write(config)
        success("Local copy saved to {0}".format(local_conf))
    except IOError as e:
        warn("Could not save local copy: {0}".format(e))


# ------------------------------------------------------------------------------
# Service management
# ------------------------------------------------------------------------------
def _command_exists(command):
    """Return True if command exists on PATH."""
    if os.path.isabs(command):
        return os.path.isfile(command) and os.access(command, os.X_OK)
    for path in os.environ.get("PATH", "").split(os.pathsep):
        if not path:
            continue
        candidate = os.path.join(path, command)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return True
    return False


def _systemd_running():
    """Return True if systemd appears to be PID 1."""
    if os.path.isdir("/run/systemd/system"):
        return True
    try:
        with open("/proc/1/comm", "r") as handle:
            return handle.read().strip() == "systemd"
    except IOError:
        return False


def _read_pidfile(pid_path):
    try:
        with open(pid_path, "r") as handle:
            return handle.read().strip()
    except IOError:
        return None


def _pid_is_running(pid_value):
    try:
        pid_value = int(pid_value)
    except (TypeError, ValueError):
        return False
    return os.path.exists("/proc/{0}".format(pid_value))


def _squid_is_running():
    pid_paths = ["/run/squid.pid", "/var/run/squid.pid", "/var/run/squid3.pid"]
    for pid_path in pid_paths:
        pid_value = _read_pidfile(pid_path)
        if pid_value and _pid_is_running(pid_value):
            return True

    if os.path.isdir("/proc"):
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                comm_path = os.path.join("/proc", entry, "comm")
                try:
                    with open(comm_path, "r") as handle:
                        comm = handle.read().strip()
                except IOError:
                    continue
                if comm.startswith("squid"):
                    return True
        except OSError:
            pass

    return False


def restart_squid():
    """Restart Squid service."""
    action("Restarting Squid service...")
    step_delay()
    if _systemd_running() and _command_exists("systemctl"):
        ret = subprocess.call(["systemctl", "restart", "squid"])
        if ret == 0:
            success("Squid service restarted")
            return
        warn("systemctl restart failed, falling back")

    if _command_exists("service"):
        ret = subprocess.call(["service", "squid", "restart"])
        if ret == 0:
            success("Squid service restarted")
            return
        warn("service restart failed, falling back")

    ret = subprocess.call(["squid", "-k", "reconfigure"])
    if ret == 0:
        success("Squid reconfigured")
        return

    ret = subprocess.call(["squid", "-f", "/etc/squid/squid.conf"])
    if ret == 0:
        success("Squid started")
        return

    error("Failed to restart Squid")
    error("Check config: squid -k parse")
    sys.exit(1)


def verify_squid():
    """Verify Squid is running."""
    info("Verifying Squid status...")
    step_delay()
    if _systemd_running() and _command_exists("systemctl"):
        ret = subprocess.call(
            ["systemctl", "is-active", "--quiet", "squid"]
        )
        if ret != 0:
            error("Squid is not running")
            error("Check logs: journalctl -u squid")
            sys.exit(1)
        success("Squid is active and running")
        return

    if _squid_is_running():
        success("Squid is active and running")
        return

    error("Squid is not running")
    error("Check logs: /var/log/squid/cache.log")
    sys.exit(1)


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
def print_summary(domain, port, ssl_bump_mode, cert_path, trust_sources=None):
    """Print configuration summary."""
    _, apex_domain, _, domain_display = build_domain_variants(domain)
    allowed_host = apex_domain or domain.lstrip(".") or domain

    print("")
    print("{bold}{green}".format(bold=C_BOLD, green=C_GREEN) + "=" * 60 + C_RESET)
    print("{bold}{green}  CONFIGURATION COMPLETE{reset}".format(
        bold=C_BOLD, green=C_GREEN, reset=C_RESET))
    print("{bold}{green}".format(bold=C_BOLD, green=C_GREEN) + "=" * 60 + C_RESET)
    print("")
    print("  {cyan}Proxy Address:{reset}  localhost:{port}".format(
        cyan=C_CYAN, reset=C_RESET, port=port))
    print("  {cyan}Whitelisted:{reset}    {display}".format(
        cyan=C_CYAN, reset=C_RESET, display=domain_display))

    mitm_modes = ("verify-mitm", "noverify")

    if ssl_bump_mode == "off":
        print("  {cyan}SSL Bump:{reset}       {dim}disabled{reset}".format(
            cyan=C_CYAN, reset=C_RESET, dim=C_DIM))
    elif ssl_bump_mode == "verify-no-mitm":
        print("  {cyan}SSL Bump:{reset}       {green}verify-no-mitm{reset} (certificate validation ON, no MITM)".format(
            cyan=C_CYAN, reset=C_RESET, green=C_GREEN))
        print("  {cyan}Bump CA Certificate:{reset} {cert}".format(
            cyan=C_CYAN, reset=C_RESET, cert=cert_path))
        if trust_sources:
            print("  {cyan}Outgoing TLS Trust:{reset} {sources}".format(
                cyan=C_CYAN, reset=C_RESET, sources=", ".join(trust_sources)))
    elif ssl_bump_mode == "verify-mitm":
        print("  {cyan}SSL Bump:{reset}       {green}verify-mitm{reset} (certificate validation ON, MITM)".format(
            cyan=C_CYAN, reset=C_RESET, green=C_GREEN))
        print("  {cyan}Bump CA Certificate:{reset} {cert}".format(
            cyan=C_CYAN, reset=C_RESET, cert=cert_path))
        if trust_sources:
            print("  {cyan}Outgoing TLS Trust:{reset} {sources}".format(
                cyan=C_CYAN, reset=C_RESET, sources=", ".join(trust_sources)))
    elif ssl_bump_mode == "noverify":
        print("  {cyan}SSL Bump:{reset}       {yellow}noverify{reset} (certificate validation OFF, MITM)".format(
            cyan=C_CYAN, reset=C_RESET, yellow=C_YELLOW))
        print("  {cyan}Bump CA Certificate:{reset} {cert}".format(
            cyan=C_CYAN, reset=C_RESET, cert=cert_path))
        print("  {cyan}Outgoing TLS Trust:{reset} {dim}disabled{reset}".format(
            cyan=C_CYAN, reset=C_RESET, dim=C_DIM))

    print("")
    print("  {dim}Test commands:{reset}".format(dim=C_DIM, reset=C_RESET))
    print("  {green}curl -x http://localhost:{port} https://{host}{reset}".format(
        green=C_GREEN, reset=C_RESET, port=port, host=allowed_host))
    print("  {red}curl -x http://localhost:{port} https://example.net  # blocked{reset}".format(
        red=C_RED, reset=C_RESET, port=port))

    if ssl_bump_mode in mitm_modes:
        print("")
        print("  {dim}To trust the CA on clients, install:{reset}".format(
            dim=C_DIM, reset=C_RESET))
        print("  {cyan}{cert}{reset}".format(cyan=C_CYAN, reset=C_RESET, cert=cert_path))

    print("")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Install and configure Squid proxy with domain whitelist",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python {0} --domain .google.com --port 8080
  sudo python {0} -d .github.com -p 3128
  sudo python {0} --ssl-bump verify-no-mitm
  sudo python {0} --ssl-bump verify-mitm
  sudo python {0} --ssl-bump noverify --ssl-port 8443
  sudo python {0} --ssl-bump noverify --ssl-port 8443 --ssl-port 9443
        """.format(sys.argv[0])
    )
    parser.add_argument(
        "-d", "--domain",
        default=".google.com",
        help="Domain to whitelist (default: .google.com)"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=8080,
        help="Proxy listen port (default: 8080)"
    )
    parser.add_argument(
        "--ssl-bump",
        choices=["off", "verify-no-mitm", "verify-mitm", "noverify", "verify"],
        default="off",
        help="SSL Bump mode: off, verify-no-mitm, verify-mitm, noverify (verify is alias for verify-no-mitm)"
    )
    parser.add_argument(
        "--ca-cert",
        help="Path to CA certificate (optional, auto-generated if not provided)"
    )
    parser.add_argument(
        "--ca-key",
        help="Path to CA private key (optional, auto-generated if not provided)"
    )
    parser.add_argument(
        "--ssl-port",
        type=int,
        action="append",
        help="Additional SSL port to allow (can be specified multiple times)"
    )
    args = parser.parse_args()

    # Get script directory for local config/cert copy
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Ensure domain format
    domain, _, _, domain_display = build_domain_variants(args.domain)

    ssl_bump_mode = normalize_ssl_bump_mode(args.ssl_bump)
    cert_path = None
    key_path = None
    cafile = None
    capath = None
    trust_sources = None

    # Run setup
    banner()
    print("")

    info("Target domain: {0}".format(domain_display))
    info("Listen port: {0}".format(args.port))
    if ssl_bump_mode != "off":
        info("SSL Bump mode: {0}".format(ssl_bump_mode))
    print("")

    check_root()
    print("")

    # Check/install Squid
    squid_installed = check_squid_installed()
    if squid_installed:
        success("Squid already installed")
        # Check SSL support if SSL Bump enabled
        if ssl_bump_mode != "off":
            if check_squid_ssl_support():
                success("SSL support confirmed")
            else:
                warn("Installed Squid may lack SSL support")
                warn("Consider reinstalling with: apt install squid-openssl")
    else:
        warn("Squid not found")
        install_squid()
    print("")

    # Handle SSL Bump certificate setup
    if ssl_bump_mode != "off":
        info("Setting up SSL Bump certificates...")
        print("")

        if args.ca_cert and args.ca_key:
            # User-provided certificates
            if not os.path.exists(args.ca_cert):
                error("CA certificate not found: {0}".format(args.ca_cert))
                sys.exit(1)
            if not os.path.exists(args.ca_key):
                error("CA key not found: {0}".format(args.ca_key))
                sys.exit(1)
            info("Using user-provided certificates")
            cert_path = args.ca_cert
            key_path = args.ca_key
        else:
            # Auto-generate certificates
            cert_dir = get_cert_dir(script_dir)
            cert_path, key_path = generate_ca_cert(cert_dir)

        # Copy certs to Squid directory
        squid_cert, squid_key = copy_certs_to_squid(cert_path, key_path)
        print("")

        # Initialize SSL database
        ssl_crtd_path = init_ssl_db()
        print("")

        # Use Squid-directory paths in config
        cert_path = squid_cert
        key_path = squid_key
    else:
        ssl_crtd_path = None

    if ssl_bump_mode in ("verify-mitm", "verify-no-mitm"):
        cafile, capath, trust_sources = find_ca_trust_sources()
        if trust_sources:
            info("Using system CA trust: {0}".format(", ".join(trust_sources)))
        else:
            warn("System CA trust not found; TLS validation may fail")

    # Generate and write configuration
    backup_config()
    config = generate_config(domain, args.port, ssl_bump_mode, cert_path, key_path,
                             ssl_crtd_path, args.ssl_port, cafile, capath)
    write_config(config, script_dir)
    print("")

    # Restart and verify
    restart_squid()
    verify_squid()

    # Get original cert path for display (from certs dir, not /etc/squid)
    display_cert = None
    if ssl_bump_mode != "off":
        cert_dir = get_cert_dir(script_dir)
        display_cert = os.path.join(cert_dir, "squid-ca-cert.pem")

    print_summary(domain, args.port, ssl_bump_mode, display_cert, trust_sources)


if __name__ == "__main__":
    main()
