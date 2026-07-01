"""
CryptoLogin CLI - Basic Usage Example
Demonstrates simple authentication flow
"""
from cryptologin.storage.sqlite_v2 import SQLiteStorageV2
from cryptologin.core.user_manager_v2 import UserManagerV2
from cryptologin.client.crypto_client import CryptoClient
import hmac
import hashlib


def main():
    print("🔐 CryptoLogin - Basic Usage Example\n")
    
    # 1. Initialize storage and user manager
    print("1️⃣  Initializing CryptoLogin...")
    storage = SQLiteStorageV2(db_path="example.db", auto_migrate=True)
    user_manager = UserManagerV2(storage=storage)
    crypto_client = CryptoClient()
    
    # 2. Define master secret (in real app, get from user securely)
    master_secret = "this-is-a-test-master-secret-1234567890"
    print(f"2️⃣  Master secret: {master_secret[:20]}...")
    
    # 3. Derive user_id from master_secret (client-side)
    print("\n3️⃣  Deriving user_id from master_secret...")
    user_id = crypto_client.derive_user_id(master_secret)
    print(f"   user_id: {user_id[:32]}...")
    
    # 4. Register user
    print("\n4️⃣  Registering user...")
    try:
        user_manager.register_user_v2(user_id, {"name": "Test User", "role": "admin"})
        print("   ✅ User registered successfully")
    except Exception as e:
        print(f"   ℹ️  User already exists: {e}")
    
    # 5. Login flow
    print("\n5️⃣  Initiating login...")
    challenge = user_manager.initiate_login_v2(user_id)
    print(f"   Challenge: {challenge[:32]}...")
    
    # 6. Compute HMAC (client-side)
    print("\n6️⃣  Computing HMAC-SHA256...")
    hmac_signature = hmac.new(
        user_id.encode('utf-8'),
        challenge.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    print(f"   HMAC: {hmac_signature[:32]}...")
    
    # 7. Verify login
    print("\n7️⃣  Verifying login...")
    session = user_manager.complete_login_v2(user_id, hmac_signature)
    print(f"   ✅ Login successful!")
    print(f"   Session ID: {session.session_id[:32]}...")
    print(f"   Expires: {session.expires_at}")
    
    # 8. Validate session
    print("\n8️⃣  Validating session...")
    is_valid = user_manager.validate_session(session.session_id)
    print(f"   Session valid: {is_valid}")
    
    # 9. Logout
    print("\n9️⃣  Logging out...")
    user_manager.logout(session.session_id)
    print("   ✅ Logged out successfully")
    
    print("\n🎉 Example completed successfully!")


if __name__ == "__main__":
    main()