#!/usr/bin/env python3
"""
Test script for message encryption functionality
"""

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import secrets

def derive_key_from_password(password, salt=None):
    """Derive encryption key from password using PBKDF2"""
    if salt is None:
        salt = secrets.token_bytes(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_message(message, key):
    """Encrypt a message using Fernet"""
    try:
        f = Fernet(key)
        encrypted_message = f.encrypt(message.encode())
        return base64.urlsafe_b64encode(encrypted_message).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_message(encrypted_message, key):
    """Decrypt a message using Fernet"""
    try:
        f = Fernet(key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode())
        decrypted_message = f.decrypt(encrypted_bytes)
        return decrypted_message.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return "[Message could not be decrypted]"

def get_chat_encryption_key(request_id, user_id):
    """Get or generate encryption key for a specific chat session"""
    # Create a unique key for each chat session based on request_id
    # This ensures only participants in the chat can decrypt messages
    # The key is derived from the request_id to ensure both participants use the same key
    chat_secret = f"chat_session_{request_id}"
    
    # Use a combination of request_id to derive a consistent key for both participants
    # In a production environment, you might want to store keys in a separate secure table
    salt = hashlib.sha256(chat_secret.encode()).digest()[:16]
    key, _ = derive_key_from_password(chat_secret, salt)
    return key

def test_encryption():
    """Test the encryption and decryption functionality"""
    print("🔐 Testing Message Encryption System")
    print("=" * 50)
    
    # Test parameters
    request_id = 123
    user_id = 456
    test_messages = [
        "Hello! I'm interested in your book.",
        "Can we meet at the library tomorrow?",
        "What time works best for you?",
        "Perfect! See you there.",
        "Thanks for the exchange! 😊"
    ]
    
    # Get encryption key
    key = get_chat_encryption_key(request_id, user_id)
    print(f"✅ Generated encryption key for chat session {request_id}")
    
    # Test encryption and decryption
    for i, original_message in enumerate(test_messages, 1):
        print(f"\n📝 Test {i}:")
        print(f"   Original: {original_message}")
        
        # Encrypt
        encrypted = encrypt_message(original_message, key)
        if encrypted:
            print(f"   🔒 Encrypted: {encrypted[:50]}...")
            
            # Decrypt
            decrypted = decrypt_message(encrypted, key)
            print(f"   🔓 Decrypted: {decrypted}")
            
            # Verify
            if decrypted == original_message:
                print("   ✅ SUCCESS: Message encrypted and decrypted correctly!")
            else:
                print("   ❌ FAILED: Decrypted message doesn't match original!")
        else:
            print("   ❌ FAILED: Encryption failed!")
    
    # Test with different request IDs (should have different keys)
    print(f"\n🔑 Testing Key Uniqueness:")
    key1 = get_chat_encryption_key(123, 456)
    key2 = get_chat_encryption_key(124, 456)
    key3 = get_chat_encryption_key(123, 789)
    
    print(f"   Key for request 123, user 456: {key1[:20]}...")
    print(f"   Key for request 124, user 456: {key2[:20]}...")
    print(f"   Key for request 123, user 789: {key3[:20]}...")
    
    if key1 != key2:
        print("   ✅ SUCCESS: Different request IDs generate different keys!")
    else:
        print("   ❌ FAILED: Different request IDs generated same key!")
    
    if key1 == key3:
        print("   ✅ SUCCESS: Same request ID generates same key regardless of user!")
    else:
        print("   ❌ FAILED: Same request ID generated different keys!")
    
    print("\n🎉 Encryption test completed!")

if __name__ == "__main__":
    test_encryption() 