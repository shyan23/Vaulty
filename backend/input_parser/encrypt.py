import os
import json
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from inputhandler import InputHandler, load_input_file
from pathlib import Path
import time
from typing import Dict, Tuple

class VaultError(Exception):
    """Custom exception for vault operations"""
    pass

class VaultEncryption:
    """
    Vault encryption system that processes InputHandler data,
    encrypts only VALUES using individual hash-based keys, and creates .vault files
    """
    
    def __init__(self):
        self.salt_size = 32  # 256-bit salt
        self.iterations = 100000  # PBKDF2 iterations
        self.assets_dir = "backend/assets"  # Directory to store all generated files
        
        # Create assets directory if it doesn't exist
        os.makedirs(self.assets_dir, exist_ok=True)
        
    def generate_hash_key(self, value: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Generate encryption key from individual value hash using PBKDF2
        """
        if salt is None:
            salt = os.urandom(self.salt_size)
        
        # Create hash of the individual value as base for key derivation
        value_hash = hashlib.sha256(value.encode('utf-8')).hexdigest()
        
        # Use PBKDF2 to derive a strong key from the hash
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=self.iterations,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(value_hash.encode()))
        return key, salt
    
    def create_value_hash(self, key: str, value: str) -> Dict[str, str]:
        """
        Create comprehensive hashes for key-value pair for Merkle tree and merging
        """
        # Hash the value
        value_hash = hashlib.sha256(value.encode('utf-8')).hexdigest()
        
        # Hash the key
        key_hash = hashlib.sha256(key.encode('utf-8')).hexdigest()
        
        # Combined hash for the key-value pair (for Merkle tree)
        combined = f"{key}:{value}"
        combined_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        
        # Additional hash with timestamp for versioning
        timestamped = f"{combined}:{int(time.time())}"
        timestamped_hash = hashlib.sha256(timestamped.encode('utf-8')).hexdigest()
        
        return {
            "key_hash": key_hash,
            "value_hash": value_hash,
            "combined_hash": combined_hash,
            "timestamped_hash": timestamped_hash,
            "created": int(time.time())
        }
    
    def create_metadata_file(self, original_file: str, key_value_hashes: Dict[str, Dict], 
                           encrypted_keys_info: Dict[str, Dict]) -> dict:
        """
        Create comprehensive metadata for vault operations, merging, and Merkle trees
        """
        # Calculate root hash for Merkle tree (simple implementation)
        all_hashes = [info["combined_hash"] for info in key_value_hashes.values()]
        all_hashes.sort()  # Ensure consistent ordering
        root_hash = hashlib.sha256(''.join(all_hashes).encode('utf-8')).hexdigest()
        
        metadata = {
            "created": int(time.time()),
            "original_file": Path(original_file).name,
            "iterations": self.iterations,
            "algorithm": "PBKDF2-SHA256",
            "total_keys": len(key_value_hashes),
            "merkle_root": root_hash,
            "key_value_hashes": key_value_hashes,  # Individual hashes for each key-value pair
            "encryption_info": encrypted_keys_info,  # Salt and other encryption metadata per key
            "integrity_check": hashlib.sha256(json.dumps(key_value_hashes, sort_keys=True).encode()).hexdigest()
        }
        
        return metadata
    
    def get_assets_path(self, filename: str) -> str:
        """Get full path for a file in the assets directory"""
        return os.path.join(self.assets_dir, filename)
    
    def encrypt_to_vault(self, input_file: str = "input.txt", vault_file: str = None) -> str:
        """
        Convert input file to vault format:
        1. .vault file: Contains encrypted key-value pairs 
        2. .metadata file: Contains hashes and encryption info (for merging/Merkle trees)
        3. Encrypted values are stored separately for security
        """
        if vault_file is None:
            base_name = Path(input_file).stem
            vault_file = f"{base_name}.vault"
        
        # Create related filenames with assets directory
        base_name = Path(vault_file).stem
        metadata_file = self.get_assets_path(f"{base_name}.metadata")
        encrypted_file = self.get_assets_path(f"{base_name}.encrypt")
        vault_file = self.get_assets_path(vault_file)
        
        try:
            print(f"Loading input file: {input_file}")
            handler = InputHandler(input_file)
            normal_dict = handler.get_all_data()
            
            # Storage dictionaries
            vault_data = {}  # Non-encrypted key-value pairs for .vault file
            encrypted_data = {}  # Encrypted values
            key_value_hashes = {}  # Hashes for each key-value pair
            encrypted_keys_info = {}  # Salt and encryption metadata per key
            
            # Process each key-value pair
            for key, value in normal_dict.items():
                print(f"Processing key: {key}")
                
                # Store non-encrypted key-value pair in vault file
                vault_data[key] = value
                
                # Generate unique encryption key for this value
                encryption_key, salt = self.generate_hash_key(value)
                
                # Encrypt the value
                fernet = Fernet(encryption_key)
                encrypted_value = fernet.encrypt(value.encode('utf-8'))
                encrypted_b64 = base64.b64encode(encrypted_value).decode('utf-8')
                
                # Store encrypted value
                encrypted_data[key] = encrypted_b64
                
                # Generate comprehensive hashes for this key-value pair
                hashes_info = self.create_value_hash(key, value)
                key_value_hashes[key] = hashes_info
                
                # Store encryption metadata
                encrypted_keys_info[key] = {
                    "salt": base64.b64encode(salt).decode('utf-8'),
                    "algorithm": "Fernet",
                    "key_derivation": "PBKDF2-SHA256",
                    "iterations": self.iterations,
                    "encrypted_at": int(time.time())
                }
            
            print(f"Processed {len(vault_data)} key-value pairs")
            
            # Create metadata with hashes and encryption info
            metadata = self.create_metadata_file(input_file, key_value_hashes, encrypted_keys_info)
            
            # Write .vault file (unencrypted key-value pairs)
            print(f"Writing vault file: {vault_file}")
            with open(vault_file, 'w', encoding='utf-8') as f:
                for key, value in vault_data.items():
                    f.write(f"{key}={value}\n")
            
            # Write .metadata file (hashes and encryption info)
            print(f"Writing metadata file: {metadata_file}")
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"Writing encrypted file: {encrypted_file}")
            encrypted_content = {
               "encrypted_data": encrypted_data
            }
            with open(encrypted_file, 'w', encoding='utf-8') as f:
                json.dump(encrypted_content, f, indent=2)
            
            # Create SSH key pair for this vault in assets folder
            ssh_private_key, ssh_public_key = self.create_ssh_keypair(input_file)
            
            print(f"✓ Vault created successfully: {vault_file}")
            print(f"✓ Metadata file created: {metadata_file}")
            print(f"✓ Encrypted file created: {encrypted_file}")
            print(f"✓ SSH private key created: {ssh_private_key}")
            print(f"✓ SSH public key created: {ssh_public_key}")
            
            return vault_file
            
        except Exception as e:
            raise VaultError(f"Failed to create vault: {str(e)}")
    
    def create_ssh_keypair(self, original_file: str) -> Tuple[str, str]:
        """
        Create SSH key pair for vault access and store in assets folder
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Create filenames in assets directory
        base_name = Path(original_file).stem
        private_key_file = self.get_assets_path(f"{base_name}_private.pem")
        public_key_file = self.get_assets_path(f"{base_name}_public.pem")
        
        # Write keys to files
        with open(private_key_file, 'wb') as f:
            f.write(private_pem)
        
        with open(public_key_file, 'wb') as f:
            f.write(public_pem)
        
        return private_key_file, public_key_file
    
    def get_vault_info(self, vault_file: str) -> dict:
        """
        Get information about a vault file and its associated metadata
        """
        try:
            # Ensure we're looking in the assets directory
            vault_path = self.get_assets_path(vault_file)
            
            # Read vault file
            vault_keys = []
            with open(vault_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        if '=' in line:
                            key = line.split('=', 1)[0].strip()
                            vault_keys.append(key)
            
            # Read metadata file
            base_name = Path(vault_file).stem
            metadata_file = self.get_assets_path(f"{base_name}.metadata")
            
            with open(metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            
            info = {
                "vault_file": vault_path,
                "metadata_file": metadata_file,
                "original_file": metadata['original_file'],
                "created": time.ctime(metadata['created']),
                "algorithm": metadata['algorithm'],
                "total_keys": metadata['total_keys'],
                "available_keys": vault_keys,
                "merkle_root": metadata['merkle_root'],
                "iterations": metadata['iterations'],
                "integrity_check": metadata['integrity_check']
            }
            
            return info
            
        except Exception as e:
            raise VaultError(f"Failed to read vault info: {str(e)}")

    def list_vault_keys(self, vault_file: str) -> list:
        """
        List all available keys in the vault file
        """
        try:
            vault_path = self.get_assets_path(vault_file)
            keys = []
            with open(vault_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        if '=' in line:
                            key = line.split('=', 1)[0].strip()
                            keys.append(key)
            
            return keys
            
        except Exception as e:
            raise VaultError(f"Failed to list vault keys: {str(e)}")
    
    def get_metadata(self, vault_file: str) -> dict:
        """
        Get metadata information for Merkle tree operations and merging
        """
        try:
            base_name = Path(vault_file).stem
            metadata_file = self.get_assets_path(f"{base_name}.metadata")
            
            with open(metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            
            return metadata
            
        except Exception as e:
            raise VaultError(f"Failed to read metadata: {str(e)}")

# Convenience functions
def create_vault(input_file: str = "input.txt", vault_file: str = None) -> str:
    """Create a vault from an input file"""
    vault = VaultEncryption()
    return vault.encrypt_to_vault(input_file, vault_file)

def vault_info(vault_file: str) -> dict:
    """Get information about a vault file"""
    vault = VaultEncryption()
    return vault.get_vault_info(vault_file)

def list_keys(vault_file: str) -> list:
    """List all keys in a vault file"""
    vault = VaultEncryption()
    return vault.list_vault_keys(vault_file)

def get_metadata(vault_file: str) -> dict:
    """Get metadata for Merkle tree and merging operations"""
    vault = VaultEncryption()
    return vault.get_metadata(vault_file)

# Example usage and testing
if __name__ == "__main__":
    print("=== Vault Encryption System Demo ===")
    
    input_file = "input.txt"
    
    try:
        # Step 1: Create vault from input file
        print("\n1. Creating vault from input file...")
        vault_file = create_vault(input_file)
        
        # Step 2: Show vault information
        print("\n2. Vault information:")
        info = vault_info(Path(vault_file).name)  # Pass just the filename, not full path
        for key, value in info.items():
            print(f"   {key}: {value}")
        
        # Step 3: List available keys
        print("\n3. Available keys in vault:")
        keys = list_keys(Path(vault_file).name)
        for key in keys:
            print(f"   • {key}")
        
        # Step 4: Show metadata for Merkle tree operations
        print("\n4. Metadata for Merkle tree operations:")
        metadata = get_metadata(Path(vault_file).name)
        print(f"   Merkle root: {metadata['merkle_root']}")
        print(f"   Integrity check: {metadata['integrity_check']}")
        
        print("\nFiles created in assets folder:")
        base_name = Path(input_file).stem
        print(f"  • {base_name}.vault")
        print(f"  • {base_name}.metadata")
        print(f"  • {base_name}.encrypt")
        print(f"  • {base_name}_private.pem")
        print(f"  • {base_name}_public.pem")
        
    except VaultError as e:
        print(f"Vault Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")