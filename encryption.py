import gnupg
import hashlib
from config_parser import GetConfigPaster

GNUPGHOME = GetConfigPaster('GPG', 'gnupg_home')
KEYRING = GetConfigPaster('GPG', 'keyring')
RECIPIENTS = GetConfigPaster('GPG', 'recipients')
SYMMETRIC = GetConfigPaster('GPG', 'symmetric_encryption')
ENCRYPTION_KEY = GetConfigPaster('ENCRYPTION_KEY', 'key')

class GPGCipher(object):
    def __init__(self, gnupghome=None, keyring=None, recipients=None, symmetric=None): 
        self.gnupghome = gnupghome
        self.keyring = keyring
        self.recipients = recipients
        self.symmetric = symmetric

    def encrypt(self, data):
        if self.gnupghome:
            cipher = gnupg.GPG(gnupghome=self.gnupghome, keyring=self.keyring)
        else:
            cipher = gnupg.GPG()
        if self.symmetric == 'True':
            print(f"### SYMMETRIC encryption ###")
            crypted = cipher.encrypt(
                data,
                recipients = None,
                symmetric = True,
                passphrase = ENCRYPTION_KEY
            )
        else:
            print(f"### PUB-KEY encryption ###")
            crypted = cipher.encrypt(
                data,
                recipients = self.recipients,
                always_trust = True
            )
        if crypted.ok:
            return crypted.data.decode()
        else:
            return f"encription error with status: {crypted.status}"
    
    def decrypt(self, data, passphrase=None):
        if self.gnupghome:
            cipher = gnupg.GPG(gnupghome=self.gnupghome, keyring=self.keyring)
        else:
            cipher = gnupg.GPG()
        if self.symmetric == 'True':
            print(f"### SYMMETRIC decryption ###")
            clear = cipher.decrypt(
                data,
                passphrase = ENCRYPTION_KEY
            )
        else:
            print(f"### PUB-KEY decryption ###")
            clear = cipher.decrypt(
                data,
            )
        if clear.ok:
            return clear.data.decode()
        else:
            return f"encription error with status: {clear.status}"
    
def EncryptPassword(data):
    '''
    Encrypt the given data/string of password with cipher
    '''
    cipher = GPGCipher(GNUPGHOME, KEYRING, RECIPIENTS, SYMMETRIC)
    encoded = cipher.encrypt(data)
    print(f"Created object cipher of type: {type(cipher)}")
    print(f"password: {data} encoded as:\n{encoded}")
    print(f"type of encoded pwd: {type(encoded)}")
    return encoded

def DecryptPassword(data):
    '''
    Decrypt the given data/string of encoded password with cipher.
    '''
    cipher = GPGCipher(GNUPGHOME, KEYRING, RECIPIENTS, SYMMETRIC)
    clear = cipher.decrypt(data)
    print(f"encrypted password:\n{data}")
    print(f"decoded as: {clear}")
    return clear