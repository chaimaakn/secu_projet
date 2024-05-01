from passlib.hash import md5_crypt
from passlib.hash import sha1_crypt
'''
def crack_password(hash_value, dictionary_file):
    with open(dictionary_file, 'r') as f:
        for line in f:
            password = line.strip()
            if md5_crypt.verify(password, hash_value):
                return password
    return None

# Exemple d'utilisation 
hash_value = "$1$zh7k6TPq$vSqNsHYIhb0HGuQMjAnp6/"  # Exemple de hachage MD5 avec sel inclus
dictionary_file = "liste.txt"  # Fichier de dictionnaire

password = crack_password(hash_value, dictionary_file)
if password:
    print("Mot de passe trouvé :", password)
else:
    print("Mot de passe non trouvé dans le dictionnaire.")'''



password = "batman"
hashed_password = sha1_crypt.hash(password)
print("Mot de passe haché avec sha1_crypt :", hashed_password)
