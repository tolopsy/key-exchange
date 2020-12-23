from diffie_hellman import DiffieHellman

def separation_line():
    print("-----------------------------------------")

# Assuming commuication between Tolu and Chidinma
t_public = 3063     # Public A (Tolu's public key)
t_private = 2090    # Tolu's private key

c_public = 9034     # Public B (Chidinma's public key)
c_private = 1348    # Chidinma's private key

Tolu = DiffieHellman(pub_a=t_public, pub_b=c_public, pri=t_private)
Chidinma = DiffieHellman(pub_a=t_public, pub_b=c_public, pri=c_private)

t_partial = Tolu.get_partial_key()      # Tolu's partial key
c_partial = Chidinma.get_partial_key()  # Chidinma's partial key

print(f"Tolu's partial key is {t_partial}\nChidinma's partial key is {c_partial}")
separation_line()

t_full = Tolu.get_full_key(c_partial)       # Full key obtained by Tolu
c_full = Chidinma.get_full_key(t_partial)   # Full key obtained by Chidinma

print(f"Full key by Tolu is {t_full}\nFull key by Chidinma is {c_full}")
separation_line()

message = "Hello Chidinma, Have you pulled the repo?"

t_encrypted = Tolu.encrypt_message(message)
print(f"Tolu's encrypted message is {t_encrypted}")

c_decrypted = Chidinma.decrypt_message(t_encrypted)
print(f"Decrypted message: {c_decrypted}")