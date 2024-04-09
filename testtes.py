import hashlib

# Fonction de réduction
def reduction_sha1(hash_value):
    hash_obj = hashlib.sha1(hash_value.encode())
    return hash_obj.hexdigest()

# Longueur maximale de la chaîne
CHAIN_LENGTH = 1000

# Nombre de chaînes
NUM_CHAINS = 1000000

# Ouvrir le fichier de mots de passe
with open('liste.txt', 'r') as file:
    passwords = file.read().splitlines()

# Initialiser la table arc-en-ciel
rainbow_table = {}

# Créer les chaînes de hachages
for chain_index in range(NUM_CHAINS):
    # Choisir un mot de passe aléatoire comme point de départ
    password = passwords[chain_index % len(passwords)]
    hash_value = hashlib.sha1(password.encode()).hexdigest()
    chain = [hash_value]

    # Construire la chaîne de longueur maximale
    for i in range(CHAIN_LENGTH - 1):
        hash_value = reduction_sha1(hash_value)
        chain.append(hash_value)

    # Stocker la chaîne dans la table arc-en-ciel
    start_hash = chain[0]
    end_hash = chain[-1]
    rainbow_table[start_hash] = (password, end_hash)


# Sauvegarder la table arc-en-ciel dans un fichier
with open('hash_table_sha1.txt', 'w') as file:
    for start_hash, (password, end_hash) in rainbow_table.items():
        file.write(f'{start_hash}: {password} -> {end_hash}\n')




'''# Fonction de réduction
def reduction_md5(hash_value):
    hash_obj = hashlib.md5(hash_value.encode())
    return hash_obj.hexdigest()

# Longueur maximale de la chaîne
CHAIN_LENGTH = 1000

# Nombre de chaînes
NUM_CHAINS = 1000000

# Ouvrir le fichier de mots de passe
with open('liste.txt', 'r') as file:
    passwords = file.read().splitlines()

# Initialiser la table arc-en-ciel
rainbow_table = {}

# Créer les chaînes de hachages
for chain_index in range(NUM_CHAINS):
    # Choisir un mot de passe aléatoire comme point de départ
    password = passwords[chain_index % len(passwords)]
    hash_value = hashlib.md5(password.encode()).hexdigest()
    chain = [hash_value]

    # Construire la chaîne de longueur maximale
    for i in range(CHAIN_LENGTH - 1):
        hash_value = reduction_md5(hash_value)
        chain.append(hash_value)

    # Stocker la chaîne dans la table arc-en-ciel
    start_hash = chain[0]
    end_hash = chain[-1]
    rainbow_table[start_hash] = (password, end_hash)


# Sauvegarder la table arc-en-ciel dans un fichier
with open('hash_table.txt', 'w') as file:
    for start_hash, (password, end_hash) in rainbow_table.items():
        file.write(f'{start_hash}: {password} -> {end_hash}\n')'''