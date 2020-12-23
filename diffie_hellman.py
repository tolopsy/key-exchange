#Diffie Helman Key Exchange is based on this mathematical relation:
# ((g^a mod p)^b) mod p = ((g^b mod p)^a) mod p = (g^(ab)) mod p

import shelve

# private_key = pri and public key = pub. 
class DiffieHellman():
    def __init__(self, pub_a, pub_b, pri):
        self.pub_a = pub_a  # Public Key A
        self.pub_b = pub_b  # Public key B
        self.pri = pri      # Private Key
        
        self.full_key = None 
        #self.quotient = [] # Used in the encryption/decryption algorithm

    def get_partial_key(self):
        partial_key = (self.pub_a ** self.pri) % self.pub_b
        return partial_key
    
    def get_full_key(self, partner_partial_key):
        self.full_key = (partner_partial_key ** self.pri) % self.pub_b
        return self.full_key

    def encrypt_message(self, message):
        encrypted = ""         # encrypted message
        key = self.full_key
        quotient = []

        for each in message:
            encrypt_token = ord(each) + key
            quotient.append(int(encrypt_token/1114112))
            encrypted += chr(encrypt_token % 1114112)
        
        with shelve.open('quotient.db') as q:
            q['quotient'] = quotient
        return encrypted

    
    def decrypt_message(self, encrypted):
        decrypted = ""
        key = self.full_key
        with shelve.open('quotient.db') as q:
            quotient = q['quotient']

        for each in encrypted:
            raw_msg = ord(each)
            msg = (quotient.pop(0) * 1114112) + raw_msg  # encrypted_token in encrypt_message()
            decrypted += chr(msg - key)

        return decrypted

