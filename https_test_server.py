#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Simple HTTPS Test Server
Spins up an HTTPS server with a self-signed certificate for testing proxy configs.
"""
from __future__ import print_function

import argparse
import datetime
import os
import socket
import ssl
import subprocess
import sys

# Python 2/3 compatibility
try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

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


def get_html_template_path():
    """Get the path to the HTML template file."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "html", "test_page.html")


def load_html_template():
    """Load the HTML template from file."""
    with open(get_html_template_path(), "r") as f:
        return f.read()


def log_request(method, path, client_ip):
    """Log incoming request."""
    print("{dim}[*]{reset} {method} {path} from {ip}".format(
        dim=C_DIM, reset=C_RESET, method=method, path=path, ip=client_ip))


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
    """Check if HTTPS server certificate and key already exist."""
    cert_path = os.path.join(cert_dir, "https-server-cert.pem")
    key_path = os.path.join(cert_dir, "https-server-key.pem")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    return None, None


def generate_cert(cert_dir, domain):
    """Generate self-signed certificate using openssl."""
    cert_path = os.path.join(cert_dir, "https-server-cert.pem")
    key_path = os.path.join(cert_dir, "https-server-key.pem")

    action("Generating self-signed certificate for {0}...".format(domain))

    # Handle wildcard domains - use parent domain for CN
    cn = domain
    if cn.startswith("*."):
        cn = cn[2:]  # Remove *. prefix for CN

    cmd = [
        "openssl", "req",
        "-new", "-newkey", "rsa:2048",
        "-days", "365",
        "-nodes", "-x509",
        "-subj", "/CN={0}".format(domain),
        "-keyout", key_path,
        "-out", cert_path
    ]

    ret = subprocess.call(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ret != 0:
        error("Failed to generate certificate")
        sys.exit(1)

    # Set permissions
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)

    success("Certificate generated")
    info("  Certificate: {0}".format(cert_path))
    info("  Private key: {0}".format(key_path))

    return cert_path, key_path


# ------------------------------------------------------------------------------
# HTTP Handler
# ------------------------------------------------------------------------------
class TestHTTPRequestHandler(BaseHTTPRequestHandler):
    """Handler that serves a simple test page."""

    # Store server config
    server_domain = "localhost"
    server_port = 8443

    def log_message(self, format, *args):
        """Override to use our custom logging."""
        pass  # We handle logging in do_GET/do_POST

    def get_client_ip(self):
        """Get client IP address."""
        return self.client_address[0]

    def send_test_page(self):
        """Send the test HTML page."""
        client_ip = self.get_client_ip()
        log_request(self.command, self.path, client_ip)

        # Build headers string
        headers_str = ""
        for name, value in self.headers.items():
            headers_str += "    {0}: {1}\n".format(name, value)

        # Get timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Load and fill HTML template
        html = load_html_template().format(
            path=self.path,
            method=self.command,
            client_ip=client_ip,
            timestamp=timestamp,
            domain=self.server_domain,
            port=self.server_port,
            headers=headers_str
        )

        # Send response
        response = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(response))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        """Handle GET requests."""
        self.send_test_page()

    def do_POST(self):
        """Handle POST requests."""
        self.send_test_page()

    def do_HEAD(self):
        """Handle HEAD requests."""
        client_ip = self.get_client_ip()
        log_request(self.command, self.path, client_ip)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()


# ------------------------------------------------------------------------------
# Server
# ------------------------------------------------------------------------------
def run_server(port, cert_path, key_path, domain):
    """Run the HTTPS server."""
    # Set handler class attributes
    TestHTTPRequestHandler.server_domain = domain
    TestHTTPRequestHandler.server_port = port

    # Create server
    server_address = ("0.0.0.0", port)
    httpd = HTTPServer(server_address, TestHTTPRequestHandler)

    # Wrap socket with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    success("Server running on https://0.0.0.0:{0}".format(port))
    info("Press Ctrl+C to stop")
    print("")

    # Build test domain (replace wildcard with www)
    test_domain = domain.replace("*.", "www.")

    print("{bold}Test via Squid proxy (redirects to this server):{reset}".format(
        bold=C_BOLD, reset=C_RESET))
    print("  {green}curl -k -x http://127.0.0.1:8080 --connect-to {domain}:{port}:127.0.0.1:{port} https://{domain}/{reset}".format(
        green=C_GREEN, reset=C_RESET, domain=test_domain, port=port))
    print("")
    print("{bold}Test Squid blocks non-whitelisted SNI:{reset}".format(
        bold=C_BOLD, reset=C_RESET))
    print("  {red}curl -k -x http://127.0.0.1:8080 --connect-to example.com:{port}:127.0.0.1:{port} https://example.com/{reset}".format(
        red=C_RED, reset=C_RESET, port=port))
    print("")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("")
        warn("Shutting down server...")
        httpd.shutdown()
        success("Server stopped")


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Simple HTTPS test server with self-signed certificate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python {0}
  sudo python {0} --domain www.example.com
  python {0} --port 8443 --domain www.google.com
  python {0} --cert /path/to/cert.pem --key /path/to/key.pem
        """.format(sys.argv[0])
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=443,
        help="Listen port (default: 443, requires root)"
    )
    parser.add_argument(
        "-d", "--domain",
        default="*.google.com",
        help="Domain for certificate CN (default: *.google.com)"
    )
    parser.add_argument(
        "--cert",
        help="Path to existing certificate (optional)"
    )
    parser.add_argument(
        "--key",
        help="Path to existing private key (optional)"
    )
    args = parser.parse_args()

    # Get script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))

    print("")
    info("HTTPS Test Server")
    info("Domain: {0}".format(args.domain))
    info("Port: {0}".format(args.port))
    print("")

    # Determine certificate paths
    cert_path = None
    key_path = None

    if args.cert and args.key:
        # User-provided certificates
        if not os.path.exists(args.cert):
            error("Certificate not found: {0}".format(args.cert))
            sys.exit(1)
        if not os.path.exists(args.key):
            error("Key not found: {0}".format(args.key))
            sys.exit(1)
        cert_path = args.cert
        key_path = args.key
        info("Using provided certificate: {0}".format(cert_path))
    else:
        # Check for existing certs
        cert_dir = get_cert_dir(script_dir)
        info("Checking for existing certificates...")
        cert_path, key_path = check_existing_certs(cert_dir)

        if cert_path and key_path:
            success("Found existing cert: {0}".format(cert_path))
        else:
            # Generate new certificate
            cert_path, key_path = generate_cert(cert_dir, args.domain)

    print("")

    # Run server
    try:
        run_server(args.port, cert_path, key_path, args.domain)
    except socket.error as e:
        error("Could not start server: {0}".format(e))
        if args.port < 1024:
            warn("Ports below 1024 require root privileges")
        sys.exit(1)


if __name__ == "__main__":
    main()
