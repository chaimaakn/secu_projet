import hashlib

# Fonction de réduction
def reduction_md5(hash_value):
    hash_obj = hashlib.md5(hash_value.encode())
    return hash_obj.hexdigest()

# Charger la table arc-en-ciel depuis le fichier
rainbow_table = {}

with open('hash_table.txt', 'r') as file:
    for line in file:
        start_hash, entry = line.strip().split(': ')
        password, end_hash = entry.split(' -> ')
        rainbow_table[start_hash] = (password, end_hash)

# Fonction pour retrouver le mot de passe à partir d'un hachage MD5
def find_password(target_hash):
    j=0
    # Vérifier si le hachage cible correspond à un hachage initial
    if target_hash in rainbow_table:
        return rainbow_table[target_hash][0]

    # Parcourir les chaînes de la table arc-en-ciel
    for start_hash, (password, end_hash) in rainbow_table.items():
        chain = [start_hash]
        current_hash = start_hash
        for _ in range(1000):
            current_hash = reduction_md5(current_hash)
            chain.append(current_hash)
            if current_hash == target_hash:
                # Reconstruire le mot de passe à partir de la chaîne
                candidate=start_hash
                for i in range(len(chain)-1):
                    password=candidate
                    candidate = hashlib.md5(chain[i].encode()).hexdigest()
                return password
                    
            
        j=j+1        
    # Hachage non trouvé dans la table
    return None

# Exemple d'utilisation
target_hash = input("Entrez un hachage MD5 : ")
password = find_password(target_hash)
if password:
    print(f"Le mot de passe correspondant est : {password}")
else:
    print("Le mot de passe n'a pas été trouvé dans la table arc-en-ciel.")