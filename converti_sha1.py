import hashlib

def sha1_hash(mot):
    # Convertir la chaîne en bytes
    mot_bytes = mot.encode('utf-8')
    
    # Calculer le hachage SHA-1
    sha1_hash = hashlib.sha1(mot_bytes).hexdigest()
    
    return sha1_hash

# Exemple d'utilisation
mot = input("Entrez le mot à hacher en SHA-1 : ")
hash_sha1 = sha1_hash(mot)
print("Le hachage SHA-1 de", mot, "est :", hash_sha1)
