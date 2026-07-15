"""
CryptoLogin Command Line Interface

Professional CLI for managing CryptoLogin authentication system.
Supports both interactive and scriptable usage.

Usage:
    cryptologin run --port 8000
    cryptologin register --secret "your-master-secret"
    cryptologin login --secret "your-master-secret"
    cryptologin users --db cryptologin.db
    cryptologin status

Author: erabytse
License: MIT
"""

import argparse
import json
import sys
import os
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path

# ============================================================
# RICH - Pretty printing (optional dependency)
# ============================================================
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

    class FakeConsole:
        """Fallback console when rich is not installed."""
        def print(self, *args, **kwargs):
            print(*args)

        def log(self, *args, **kwargs):
            print(*args)

    console = FakeConsole()


# ============================================================
# COLORS AND FORMATTING
# ============================================================
class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY outputs)."""
        for attr in ['RED', 'GREEN', 'YELLOW', 'BLUE', 'MAGENTA', 'CYAN', 'BOLD', 'RESET']:
            setattr(cls, attr, '')


# Disable colors if not a TTY
if not sys.stdout.isatty():
    Colors.disable()


def success(msg: str):
    """Print a success message."""
    print(f"{Colors.GREEN}✓ {msg}{Colors.RESET}")


def error(msg: str):
    """Print an error message."""
    print(f"{Colors.RED}✗ {msg}{Colors.RESET}", file=sys.stderr)


def warning(msg: str):
    """Print a warning message."""
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.RESET}")


def info(msg: str):
    """Print an info message."""
    print(f"{Colors.BLUE}ℹ {msg}{Colors.RESET}")


def banner():
    """Display CryptoLogin banner."""
    print(f"{Colors.CYAN}")
    print("=" * 60)
    print(f"{Colors.BOLD}  🔐 CryptoLogin CLI{Colors.RESET}")
    print(f"{Colors.CYAN}  Zero-Storage Authentication System{Colors.RESET}")
    print("=" * 60)
    print(f"{Colors.RESET}")


# ============================================================
# EXIT CODES (POSIX standards)
# ============================================================
class ExitCode:
    SUCCESS = 0
    GENERAL_ERROR = 1
    INVALID_USAGE = 2
    AUTH_FAILED = 3
    NOT_FOUND = 4
    IO_ERROR = 5


# ============================================================
# UTILITY FUNCTIONS
# ============================================================
def load_env_file(path: str = ".env") -> Dict[str, str]:
    """Load environment variables from .env file."""
    env_vars = {}
    env_path = Path(path)

    if not env_path.exists():
        return env_vars

    try:
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip().strip('"').strip("'")
    except Exception as e:
        warning(f"Could not load {path}: {e}")

    return env_vars


def validate_db_path(db_path: str, must_exist: bool = False) -> str:
    """Validate database path."""
    path = Path(db_path)

    if must_exist and not path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    # Check write permissions
    parent = path.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)

    return str(path.resolve())


def validate_secret(secret: str) -> str:
    """Validate master secret."""
    if not secret:
        raise ValueError("Master secret cannot be empty")

    if len(secret) < 32:
        raise ValueError(f"Master secret must be at least 32 characters (got {len(secret)})")

    return secret


def format_user_id(user_id: str) -> str:
    """Format user_id for display (truncate middle)."""
    if len(user_id) <= 20:
        return user_id
    return f"{user_id[:8]}...{user_id[-8:]}"


def parse_json_data(data_str: Optional[str]) -> Optional[Dict[str, Any]]:
    """Parse JSON data string."""
    if not data_str:
        return None

    try:
        return json.loads(data_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")


# ============================================================
# AUTH INSTANCE FACTORY
# ============================================================
def get_auth_instance(db_path: str, use_v2: bool = True):
    """Get CryptoLogin authentication instance."""
    try:
        from cryptologin import CryptoLogin
        from cryptologin.storage.sqlite_v2 import SQLiteStorageV2
        from cryptologin.core.user_manager_v2 import UserManagerV2

        validated_path = validate_db_path(db_path)

        if use_v2:
            storage = SQLiteStorageV2(db_path=validated_path, auto_migrate=True)
            user_manager = UserManagerV2(storage=storage)
            return user_manager
        else:
            return CryptoLogin(db_path=validated_path)

    except ImportError as e:
        error(f"Missing dependency: {e}")
        error("Install with: pip install cryptologin")
        sys.exit(ExitCode.GENERAL_ERROR)
    except Exception as e:
        error(f"Failed to initialize auth: {e}")
        sys.exit(ExitCode.GENERAL_ERROR)


# ============================================================
# COMMAND IMPLEMENTATIONS
# ============================================================
def cmd_version(args):
    """Show version information."""
    try:
        from cryptologin import __version__
        print(f"cryptologin {__version__}")
    except ImportError:
        print("cryptologin (version unknown)")
    return ExitCode.SUCCESS


def cmd_status(args):
    """Show system status."""
    banner()

    try:
        from cryptologin import __version__
        info(f"Version: {__version__}")
    except ImportError:
        warning("Version: unknown (not installed as package)")

    db_path = args.db
    info(f"Database: {db_path}")

    if Path(db_path).exists():
        size_mb = Path(db_path).stat().st_size / (1024 * 1024)
        success(f"Database exists ({size_mb:.2f} MB)")
    else:
        warning("Database does not exist yet")

    # Check Python version
    py_version = sys.version.split()[0]
    info(f"Python: {py_version}")

    # Check required modules
    modules = ['cryptologin', 'sqlite3', 'hashlib', 'hmac']
    for module in modules:
        try:
            __import__(module)
            success(f"Module '{module}' available")
        except ImportError:
            error(f"Module '{module}' missing")

    return ExitCode.SUCCESS


def cmd_run(args):
    """Run the API server."""
    banner()

    try:
        import uvicorn
    except ImportError:
        error("uvicorn not installed. Run: pip install 'cryptologin[server]'")
        return ExitCode.GENERAL_ERROR

    # Load environment
    env_vars = load_env_file()
    for key, value in env_vars.items():
        if key not in os.environ:
            os.environ[key] = value

    # Set secret key
    if args.secret_key:
        os.environ["CRYPTOLOGIN_SECRET_KEY"] = args.secret_key

    # Set database
    os.environ["DATABASE_URL"] = f"sqlite:///{args.db}"

    info(f"Starting CryptoLogin API server...")
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"  {Colors.BOLD}Database:{Colors.RESET}    {args.db}")
    print(f"  {Colors.BOLD}Host:{Colors.RESET}        {args.host}:{args.port}")
    print(f"  {Colors.BOLD}Debug:{Colors.RESET}       {'ON' if args.debug else 'OFF'}")
    print(f"  {Colors.BOLD}API Docs:{Colors.RESET}    http://{args.host}:{args.port}/docs")
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print()
    info("Press Ctrl+C to stop the server")
    print()

    try:
        uvicorn.run(
            "cryptologin.main:app",
            host=args.host,
            port=args.port,
            reload=args.debug,
            log_level="debug" if args.debug else "info"
        )
    except KeyboardInterrupt:
        print()
        info("Server stopped by user")
        return ExitCode.SUCCESS
    except Exception as e:
        error(f"Server error: {e}")
        return ExitCode.GENERAL_ERROR


def cmd_register(args):
    """Register a new user."""
    try:
        secret = validate_secret(args.secret)
        data = parse_json_data(args.data)
        auth = get_auth_instance(args.db)

        info("Registering new user...")
        
        # ✅ CORRECTION 1 : Le bon chemin d'importation (client, pas core)
        from cryptologin.client.crypto_client import CryptoClient
        
        # ✅ CORRECTION 2 : Appel direct de la classmethod (pas besoin d'instancier)
        user_id = CryptoClient.derive_user_id(secret)
        
        # Register
        auth.register_user_v2(user_id, data or {})
        
        print()
        success("User registered successfully")
        print()
        print(f"  {Colors.BOLD}User ID:{Colors.RESET}  {format_user_id(user_id)}")
        print(f"  {Colors.BOLD}Database:{Colors.RESET} {args.db}")
        print()
        if args.json:
            print(json.dumps({
                "success": True,
                "user_id": user_id,
                "database": args.db
            }, indent=2))
        warning("Save your master secret securely. It cannot be recovered!")
        return ExitCode.SUCCESS
        
    except ValueError as e:
        error(f"Validation error: {e}")
        return ExitCode.INVALID_USAGE
    except Exception as e:
        error(f"Registration failed: {e}")
        return ExitCode.GENERAL_ERROR


def cmd_login(args):
    """Login a user."""
    try:
        secret = validate_secret(args.secret)
        auth = get_auth_instance(args.db)

        info("Initiating login...")
        
        from cryptologin.client.crypto_client import CryptoClient
        
        user_id = CryptoClient.derive_user_id(secret)
        
        # Get challenge
        challenge = auth.initiate_login_v2(user_id)
        info(f"Challenge: {format_user_id(challenge)}")
        
        # Compute HMAC (simulate client)
        import hmac
        import hashlib
        client_hmac = hmac.new(
            user_id.encode('utf-8'),
            challenge.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Complete login
        session = auth.complete_login_v2(user_id, client_hmac)
        
        print()
        success("Login successful")
        print()
        print(f"  {Colors.BOLD}User ID:{Colors.RESET}      {format_user_id(session.user_id)}")
        # ✅ In V2, the user_id is used as the session key. There is no separate session_id.
        print(f"  {Colors.BOLD}Session Active:{Colors.RESET} Yes (Key: {format_user_id(session.user_id)})")
        print(f"  {Colors.BOLD}Expires:{Colors.RESET}       {session.expires_at}")
        print()
        if args.json:
            print(json.dumps({
                "success": True,
                "user_id": session.user_id,
                "expires_at": session.expires_at.isoformat()
            }, indent=2))
        else:
            info(f"Use this User ID as Bearer token for V2: Bearer {session.user_id}")
        return ExitCode.SUCCESS
        
    except ValueError as e:
        error(f"Validation error: {e}")
        return ExitCode.INVALID_USAGE
    except Exception as e:
        error(f"Login failed: {e}")
        return ExitCode.AUTH_FAILED


def cmd_users(args):
    """List all users."""
    try:
        auth = get_auth_instance(args.db)

        # Try to access storage
        if hasattr(auth, 'storage'):
            storage = auth.storage
        else:
            error("Cannot access user storage")
            return ExitCode.GENERAL_ERROR

        info(f"Listing users from {args.db}...")
        print()

        # This depends on your storage implementation
        # Here's a generic approach
        try:
            # For SQLite
            import sqlite3
            conn = sqlite3.connect(args.db)
            cursor = conn.execute("SELECT user_id, created_at, updated_at FROM users")
            users = cursor.fetchall()
            conn.close()

            if not users:
                warning("No users found in database")
                return ExitCode.SUCCESS

            if args.json:
                print(json.dumps([{
                    "user_id": u[0],
                    "created_at": u[1],
                    "updated_at": u[2]
                } for u in users], indent=2))
            else:
                if RICH_AVAILABLE:
                    table = Table(title="Registered Users")
                    table.add_column("User ID", style="cyan")
                    table.add_column("Created", style="green")
                    table.add_column("Updated", style="yellow")

                    for user_id, created, updated in users:
                        table.add_row(
                            format_user_id(user_id),
                            str(created)[:19] if created else "N/A",
                            str(updated)[:19] if updated else "N/A"
                        )

                    console = Console()
                    console.print(table)
                else:
                    print(f"{'User ID':<20} {'Created':<20} {'Updated':<20}")
                    print("-" * 60)
                    for user_id, created, updated in users:
                        print(f"{format_user_id(user_id):<20} "
                              f"{str(created)[:19]:<20} "
                              f"{str(updated)[:19]:<20}")

            print()
            success(f"Total users: {len(users)}")

        except Exception as e:
            error(f"Could not list users: {e}")
            return ExitCode.GENERAL_ERROR

        return ExitCode.SUCCESS

    except Exception as e:
        error(f"Failed to list users: {e}")
        return ExitCode.GENERAL_ERROR


def cmd_delete(args):
    """Delete a user."""
    try:
        secret = validate_secret(args.secret)
        auth = get_auth_instance(args.db)

        if not args.yes:
            warning(f"About to delete user: {format_user_id(args.user_id)}")
            confirm = input(f"{Colors.YELLOW}Type 'yes' to confirm: {Colors.RESET}")
            if confirm.lower() != 'yes':
                info("Deletion cancelled")
                return ExitCode.SUCCESS

        # Delete user
        if hasattr(auth, 'storage'):
            auth.storage.delete_user(args.user_id)
            success(f"User deleted: {format_user_id(args.user_id)}")
        else:
            error("Storage not available")
            return ExitCode.GENERAL_ERROR

        return ExitCode.SUCCESS

    except ValueError as e:
        error(f"Validation error: {e}")
        return ExitCode.INVALID_USAGE
    except Exception as e:
        error(f"Failed to delete user: {e}")
        return ExitCode.GENERAL_ERROR


def cmd_init(args):
    """Initialize CryptoLogin in the current directory."""
    banner()

    info("Initializing CryptoLogin...")

    # Create .env file
    env_path = Path(".env")
    if not env_path.exists():
        with open(env_path, 'w') as f:
            f.write("# CryptoLogin Configuration\n")
            f.write("DATABASE_URL=sqlite:///cryptologin.db\n")
            f.write(f"CRYPTOLOGIN_SECRET_KEY={os.urandom(32).hex()}\n")
            f.write("DEBUG=false\n")
        success(f"Created {env_path}")
    else:
        warning(f"{env_path} already exists, skipping")

    # Create database
    db_path = Path(args.db)
    if not db_path.exists():
        auth = get_auth_instance(str(db_path))
        success(f"Created database: {db_path}")
    else:
        warning(f"Database {db_path} already exists")

    # Create .gitignore entry
    gitignore_path = Path(".gitignore")
    ignore_entries = [
        "cryptologin.db",
        ".env",
        "*.db-journal"
    ]

    if gitignore_path.exists():
        with open(gitignore_path, 'r') as f:
            existing = f.read()
    else:
        existing = ""

    added = []
    for entry in ignore_entries:
        if entry not in existing:
            added.append(entry)

    if added:
        with open(gitignore_path, 'a') as f:
            if existing and not existing.endswith('\n'):
                f.write('\n')
            f.write("\n# CryptoLogin\n")
            for entry in added:
                f.write(f"{entry}\n")
        success(f"Updated {gitignore_path}")

    print()
    success("CryptoLogin initialized successfully!")
    print()
    info("Next steps:")
    print("  1. Edit .env with your configuration")
    print("  2. Start the server: cryptologin run")
    print("  3. Register a user: cryptologin register --secret 'your-secret'")

    return ExitCode.SUCCESS


def cmd_get_data(args):
    """Get user data."""
    try:
        auth = get_auth_instance(args.db)

        if hasattr(auth, 'storage'):
            record = auth.storage.get_user(args.user_id)
            if not record:
                error(f"User not found: {format_user_id(args.user_id)}")
                return ExitCode.NOT_FOUND

            data = {
                "user_id": record.user_id,
                "user_data": record.user_data if hasattr(record, 'user_data') else {},
                "created_at": record.created_at.isoformat() if hasattr(record, 'created_at') and record.created_at else None,
                "updated_at": record.updated_at.isoformat() if hasattr(record, 'updated_at') and record.updated_at else None,
            }

            print(json.dumps(data, indent=2, default=str))
            return ExitCode.SUCCESS
        else:
            error("Storage not available")
            return ExitCode.GENERAL_ERROR

    except Exception as e:
        error(f"Failed to get data: {e}")
        return ExitCode.GENERAL_ERROR


# ============================================================
# MAIN ENTRY POINT
# ============================================================
def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='cryptologin',
        description='🔐 CryptoLogin - Zero-Storage Authentication System',
        epilog='Documentation: https://github.com/erabytse/CryptoLogin',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--version', '-v',
        action='version',
        version='%(prog)s ' + _get_version()
    )

    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    subparsers = parser.add_subparsers(
        dest='command',
        title='commands',
        description='Available commands',
        metavar='COMMAND'
    )

    # --- RUN COMMAND ---
    run_parser = subparsers.add_parser(
        'run',
        help='Run the API server',
        description='Start the CryptoLogin HTTP API server'
    )
    run_parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
    run_parser.add_argument('--port', type=int, default=8000, help='Port to bind (default: 8000)')
    run_parser.add_argument('--debug', action='store_true', help='Enable debug mode with auto-reload')
    run_parser.add_argument('--db', default='cryptologin.db', help='Database path (default: cryptologin.db)')
    run_parser.add_argument('--secret-key', help='JWT secret key (or set CRYPTOLOGIN_SECRET_KEY env)')

    # --- REGISTER COMMAND ---
    register_parser = subparsers.add_parser(
        'register',
        help='Register a new user',
        description='Register a new user with a master secret'
    )
    register_parser.add_argument('--secret', required=True, help='Master secret (min 32 chars)')
    register_parser.add_argument('--data', help='User data as JSON string')
    register_parser.add_argument('--db', default='cryptologin.db', help='Database path')
    register_parser.add_argument('--json', action='store_true', help='Output as JSON')

    # --- LOGIN COMMAND ---
    login_parser = subparsers.add_parser(
        'login',
        help='Login and get session',
        description='Authenticate a user and obtain a session'
    )
    login_parser.add_argument('--secret', required=True, help='Master secret')
    login_parser.add_argument('--db', default='cryptologin.db', help='Database path')
    login_parser.add_argument('--json', action='store_true', help='Output as JSON')

    # --- USERS COMMAND ---
    users_parser = subparsers.add_parser(
        'users',
        help='List all registered users',
        description='Display all users in the database'
    )
    users_parser.add_argument('--db', default='cryptologin.db', help='Database path')
    users_parser.add_argument('--json', action='store_true', help='Output as JSON')

    # --- DELETE COMMAND ---
    delete_parser = subparsers.add_parser(
        'delete',
        help='Delete a user',
        description='Permanently delete a user from the database'
    )
    delete_parser.add_argument('--user-id', required=True, help='User ID to delete')
    delete_parser.add_argument('--secret', required=True, help='Master secret for verification')
    delete_parser.add_argument('--db', default='cryptologin.db', help='Database path')
    delete_parser.add_argument('--yes', '-y', action='store_true', help='Skip confirmation')

    # --- GET-DATA COMMAND ---
    data_parser = subparsers.add_parser(
        'get-data',
        help='Get user data',
        description='Retrieve user data from the database'
    )
    data_parser.add_argument('--user-id', required=True, help='User ID')
    data_parser.add_argument('--db', default='cryptologin.db', help='Database path')

    # --- INIT COMMAND ---
    init_parser = subparsers.add_parser(
        'init',
        help='Initialize CryptoLogin in current directory',
        description='Create .env file and initialize database'
    )
    init_parser.add_argument('--db', default='cryptologin.db', help='Database path')

    # --- STATUS COMMAND ---
    subparsers.add_parser(
        'status',
        help='Show system status',
        description='Display system and database status'
    )

    # --- VERSION COMMAND ---
    subparsers.add_parser(
        'version',
        help='Show version',
        description='Display version information'
    )

    # Parse arguments
    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        Colors.disable()

    # Handle commands
    if not args.command:
        banner()
        parser.print_help()
        return ExitCode.SUCCESS

    command_map = {
        'version': cmd_version,
        'status': cmd_status,
        'run': cmd_run,
        'register': cmd_register,
        'login': cmd_login,
        'users': cmd_users,
        'delete': cmd_delete,
        'get-data': cmd_get_data,
        'init': cmd_init,
    }

    handler = command_map.get(args.command)
    if handler:
        try:
            exit_code = handler(args)
            sys.exit(exit_code if isinstance(exit_code, int) else ExitCode.SUCCESS)
        except KeyboardInterrupt:
            print()
            info("Operation cancelled by user")
            sys.exit(ExitCode.SUCCESS)
        except Exception as e:
            error(f"Unexpected error: {e}")
            sys.exit(ExitCode.GENERAL_ERROR)
    else:
        error(f"Unknown command: {args.command}")
        sys.exit(ExitCode.INVALID_USAGE)


def _get_version():
    """Get package version."""
    try:
        from cryptologin import __version__
        return __version__
    except ImportError:
        return "unknown"


if __name__ == "__main__":
    main()