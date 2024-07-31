import gnupg
import hashlib
from config_parser import GetConfigPaster

KEY = GetConfigPaster('ENCRYPTION_KEY', 'key')

class GPGCipher(object):
    def __init__(self, gnupghome, keyring): 
        self.gnupghome = gnupghome
        self.keyring = keyring
        if gnupghome:
            return gnupg.GPG(gnupghome=gnupghome, keyring=keyring)
        else:
            return gnupg.GPG()


    def encrypt(self, data, recipients):
        crypted = self.encrypt(
            data,
            recipients = recipients,
            always_trust = True
        )
        return crypted
    
    def decrypt(self, data, passphrase=None):
        if passphrase:
            clear = self.decrypt(
                data,
                passphrase = passphrase
            )
        else:
            clear = self.decrypt(
                data,
            )
        return clear
    
def EncryptPassword(data, cipher, recipients=None):
    '''
    Encrypt the given data/string of password with cipher
    '''
    return cipher.encrypt(data, recipients)

def DecryptPassword(data, cipher, passphrase):
    '''
    Decrypt the given data/string of encoded password with cipher.
    '''
    return cipher.decrypt(data, passphrase)
