"""
Command Line Interface for CryptoLogin
"""
import argparse
import json
import sys
import os
from typing import Optional


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="CryptoLogin - Zero-Knowledge Authentication System",
        epilog="For more information: https://cryptologin.io"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Run API server
    run_parser = subparsers.add_parser("run", help="Run the API server")
    run_parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    run_parser.add_argument("--port", type=int, default=8000, help="Port to bind")
    run_parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    run_parser.add_argument("--db", default="cryptologin.db", help="Database path")
    run_parser.add_argument("--secret-key", help="JWT secret key (or set CRYPTOLOGIN_SECRET_KEY env)")
    
    # Register user
    register_parser = subparsers.add_parser("register", help="Register a new user")
    register_parser.add_argument("--secret", required=True, help="Master secret")
    register_parser.add_argument("--data", help="User data as JSON string")
    register_parser.add_argument("--db", default="cryptologin.db", help="Database path")
    
    # Login
    login_parser = subparsers.add_parser("login", help="Login and get session")
    login_parser.add_argument("--secret", required=True, help="Master secret")
    login_parser.add_argument("--db", default="cryptologin.db", help="Database path")
    
    # Get user data
    data_parser = subparsers.add_parser("get-data", help="Get user data")
    data_parser.add_argument("--user-id", required=True, help="User ID")
    data_parser.add_argument("--secret", required=True, help="Master secret")
    data_parser.add_argument("--db", default="cryptologin.db", help="Database path")
    
    # Update user data
    update_parser = subparsers.add_parser("update-data", help="Update user data")
    update_parser.add_argument("--user-id", required=True, help="User ID")
    update_parser.add_argument("--secret", required=True, help="Master secret")
    update_parser.add_argument("--data", required=True, help="User data as JSON string")
    update_parser.add_argument("--db", default="cryptologin.db", help="Database path")
    
    # Delete user
    delete_parser = subparsers.add_parser("delete", help="Delete a user")
    delete_parser.add_argument("--user-id", required=True, help="User ID")
    delete_parser.add_argument("--secret", required=True, help="Master secret")
    delete_parser.add_argument("--db", default="cryptologin.db", help="Database path")
    
    # Version
    version_parser = subparsers.add_parser("version", help="Show version")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    if args.command == "version":
        from cryptologin import __version__
        print(f"cryptologin {__version__}")
        sys.exit(0)
    
    try:
        if args.command == "run":
            _run_server(args)
        elif args.command == "register":
            _register_user(args)
        elif args.command == "login":
            _login_user(args)
        elif args.command == "get-data":
            _get_data(args)
        elif args.command == "update-data":
            _update_data(args)
        elif args.command == "delete":
            _delete_user(args)
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def _get_auth(db_path: str):
    """Get CryptoLogin instance."""
    from cryptologin import CryptoLogin
    return CryptoLogin(db_path=db_path)


def _run_server(args):
    """Run the API server."""
    import uvicorn
    
    # Set secret key if provided
    if args.secret_key:
        os.environ["CRYPTOLOGIN_SECRET_KEY"] = args.secret_key
    
    # Set database path
    os.environ["DATABASE_URL"] = f"sqlite:///{args.db}"
    
    from cryptologin.main import app
    
    print(f" Starting CryptoLogin API")
    print(f" Database: {args.db}")
    print(f" Host: {args.host}:{args.port}")
    print(f" Documentation: http://{args.host}:{args.port}/docs")
    print(" Press Ctrl+C to stop")
    print("-" * 50)
    
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.debug,
        log_level="info"
    )


def _register_user(args):
    """Register a new user."""
    auth = _get_auth(args.db)
    
    data = None
    if args.data:
        try:
            data = json.loads(args.data)
        except json.JSONDecodeError:
            print("Error: Invalid JSON data", file=sys.stderr)
            sys.exit(1)
    
    try:
        user_id = auth.register(args.secret, data)
        print(f" User registered successfully")
        print(f"  User ID: {user_id}")
        print(f"  Database: {args.db}")
        print("\n Save this User ID for future operations.")
    except Exception as e:
        print(f"Registration failed: {e}", file=sys.stderr)
        sys.exit(1)


def _login_user(args):
    """Login a user."""
    auth = _get_auth(args.db)
    
    try:
        challenge = auth.login_init(args.secret)
        print(f" Challenge received")
        print(f"  Challenge: {challenge[:64]}...")
        
        # Complete login automatically
        session = auth.login_verify(args.secret, challenge)
        print(f"\n Login successful")
        print(f"  Session ID: {session.user_id}")
        print("\n Use this Session ID as Bearer token for API requests.")
    except Exception as e:
        print(f"Login failed: {e}", file=sys.stderr)
        sys.exit(1)


def _get_data(args):
    """Get user data."""
    auth = _get_auth(args.db)
    
    try:
        data = auth.get_user_data(args.user_id, args.secret)
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"Failed to get data: {e}", file=sys.stderr)
        sys.exit(1)


def _update_data(args):
    """Update user data."""
    auth = _get_auth(args.db)
    
    try:
        data = json.loads(args.data)
    except json.JSONDecodeError:
        print("Error: Invalid JSON data", file=sys.stderr)
        sys.exit(1)
    
    try:
        result = auth.update_user_data(args.user_id, args.secret, data)
        if result:
            print("Data updated successfully")
        else:
            print("Data update failed")
    except Exception as e:
        print(f"Failed to update data: {e}", file=sys.stderr)
        sys.exit(1)


def _delete_user(args):
    """Delete a user."""
    auth = _get_auth(args.db)
    
    try:
        result = auth.delete_user(args.user_id, args.secret)
        if result:
            print(f"User deleted successfully: {args.user_id}")
        else:
            print("User deletion failed")
    except Exception as e:
        print(f"Failed to delete user: {e}", file=sys.stderr)
        sys.exit(1)


# Ensure main is exported for entry point
if __name__ == "__main__":
    main()