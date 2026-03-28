import os
from typing import Any
from cryptography.fernet import Fernet

class LocalStorage:
    def __init__(self, base_dir: str, key: bytes):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)
        self.fernet = Fernet(key)

    def save_encrypted(self, filename: str, data: bytes) -> tuple[str, int]:
        encrypted = self.fernet.encrypt(data)
        path = os.path.join(self.base_dir, filename)
        with open(path, 'wb') as f:
            f.write(encrypted)
        return path, len(encrypted)

    def read_decrypted(self, path: str) -> bytes:
        with open(path, 'rb') as f:
            encrypted = f.read()
        return self.fernet.decrypt(encrypted)
