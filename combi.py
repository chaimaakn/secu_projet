from passlib.hash import md5_crypt
from passlib.hash import sha1_crypt
'''r=10000
def crack_password(hash_value, dictionary_file):
    with open(dictionary_file, 'r') as f:
        for line in f:
            password = line.strip()
            if sha1_crypt.using(rounds=r).verify(password, hash_value):
                return password
    return None

# Exemple d'utilisation 
hash_value = "$sha1${r}$mNJ22a0S$.eZu8s6oiSoDsf..fxcf3KG2ebPY"  # Exemple de hachage MD5 avec sel inclus
dictionary_file = "liste.txt"  # Fichier de dictionnaire

password = crack_password(hash_value, dictionary_file)
if password:
    print("Mot de passe trouvé :", password)
else:
    print("Mot de passe non trouvé dans le dictionnaire.")'''



password = "bat"
hashed_password = md5_crypt.encrypt(password, rounds=1)
print("Mot de passe haché avec sha1_crypt :", hashed_password)
