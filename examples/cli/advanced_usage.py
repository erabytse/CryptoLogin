"""
CryptoLogin CLI - Advanced Usage Example
Demonstrates error handling, multiple users, and session management
"""
from cryptologin.storage.sqlite_v2 import SQLiteStorageV2
from cryptologin.core.user_manager_v2 import UserManagerV2
from cryptologin.client.crypto_client import CryptoClient
from cryptologin.core.exceptions import UserNotFoundError, AuthenticationError
import hmac
import hashlib
import time


def compute_hmac(user_id: str, challenge: str) -> str:
    """Compute HMAC-SHA256 signature"""
    return hmac.new(
        user_id.encode('utf-8'),
        challenge.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def main():
    print("🔐 CryptoLogin - Advanced Usage Example\n")
    
    # Initialize
    storage = SQLiteStorageV2(db_path="advanced_example.db", auto_migrate=True)
    user_manager = UserManagerV2(storage=storage, session_duration_hours=1)
    crypto_client = CryptoClient()
    
    # Example 1: Multiple users
    print("=" * 60)
    print("Example 1: Multiple Users")
    print("=" * 60)
    
    users = [
        {"secret": "user-one-master-secret-1234567890abcdef", "name": "Alice"},
        {"secret": "user-two-master-secret-1234567890abcdef", "name": "Bob"},
        {"secret": "user-three-master-secret-1234567890abcdef", "name": "Charlie"},
    ]
    
    sessions = []
    
    for user_data in users:
        print(f"\n👤 Processing user: {user_data['name']}")
        
        # Derive user_id
        user_id = crypto_client.derive_user_id(user_data['secret'])
        
        # Register
        try:
            user_manager.register_user_v2(user_id, {"name": user_data['name']})
            print(f"   ✅ Registered")
        except Exception as e:
            print(f"   ℹ️  Already exists")
        
        # Login
        challenge = user_manager.initiate_login_v2(user_id)
        hmac_sig = compute_hmac(user_id, challenge)
        session = user_manager.complete_login_v2(user_id, hmac_sig)
        sessions.append(session)
        print(f"   ✅ Logged in (session: {session.session_id[:16]}...)")
    
    # Example 2: Session validation
    print("\n" + "=" * 60)
    print("Example 2: Session Validation")
    print("=" * 60)
    
    for i, session in enumerate(sessions):
        is_valid = user_manager.validate_session(session.session_id)
        print(f"Session {i+1} ({session.user_id[:16]}...): {'✅ Valid' if is_valid else '❌ Invalid'}")
    
    # Example 3: Error handling
    print("\n" + "=" * 60)
    print("Example 3: Error Handling")
    print("=" * 60)
    
    # Try to login with non-existent user
    print("\n🔍 Attempting login with non-existent user...")
    try:
        fake_user_id = "0" * 64
        user_manager.initiate_login_v2(fake_user_id)
    except UserNotFoundError as e:
        print(f"   ✅ Caught expected error: {e}")
    
    # Try to login with wrong HMAC
    print("\n🔍 Attempting login with wrong HMAC...")
    try:
        user_id = crypto_client.derive_user_id(users[0]['secret'])
        challenge = user_manager.initiate_login_v2(user_id)
        wrong_hmac = "0" * 64
        user_manager.complete_login_v2(user_id, wrong_hmac)
    except AuthenticationError as e:
        print(f"   ✅ Caught expected error: {e}")
    
    # Example 4: Session expiration
    print("\n" + "=" * 60)
    print("Example 4: Session Expiration (simulated)")
    print("=" * 60)
    
    print("\n⏰ Waiting 2 seconds to simulate time passing...")
    time.sleep(2)
    
    # Check all sessions
    for i, session in enumerate(sessions):
        try:
            is_valid = user_manager.validate_session(session.session_id)
            print(f"Session {i+1}: {'✅ Valid' if is_valid else '❌ Expired'}")
        except Exception as e:
            print(f"Session {i+1}: ❌ Error - {e}")
    
    # Example 5: Logout all users
    print("\n" + "=" * 60)
    print("Example 5: Logout All Users")
    print("=" * 60)
    
    for i, session in enumerate(sessions):
        user_manager.logout(session.session_id)
        print(f"✅ User {i+1} logged out")
    
    print("\n🎉 Advanced example completed!")


if __name__ == "__main__":
    main()