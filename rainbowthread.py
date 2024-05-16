import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import threading

# Variable partagée pour indiquer si le mot de passe a été trouvé
password_found = threading.Event()

# Fonction de réduction
def reduction_md5(hash_value):
    hash_obj = hashlib.md5(hash_value.encode())
    return hash_obj.hexdigest()

# Fonction pour retrouver le mot de passe à partir d'un hachage MD5
def find_password(target_hash, start, end, rainbow_table):
    # Vérifier si le hachage cible correspond à un hachage initial dans la plage
    for i in range(start, end):
        start_hash, (password, end_hash) = rainbow_table[i]
        if target_hash == start_hash or target_hash == end_hash:
            return password

    for i in range(start, end):
        if password_found.is_set():
            return None

        start_hash, (password, end_hash) = rainbow_table[i]
        chain = [start_hash]
        current_hash = start_hash
        for _ in range(1000):
            current_hash = reduction_md5(current_hash)
            chain.append(current_hash)
            if current_hash == target_hash:
                # Reconstruire le mot de passe à partir de la chaîne
                candidate = start_hash
                for j in range(len(chain) - 1):
                    #password = candidate
                    candidate = hashlib.md5(chain[j].encode()).hexdigest()
                return password

    return None

# Charger la table arc-en-ciel depuis le fichier
rainbow_table = []
with open('hash_table.txt', 'r') as file:
    for line in file:
        start_hash, entry = line.strip().split(': ')
        password, end_hash = entry.split(' -> ')
        rainbow_table.append((start_hash, (password, end_hash)))

# Exemple d'utilisation
target_hash = input("Entrez un hachage MD5 : ")
num_threads = min(24, os.cpu_count() * 2)   # Nombre de threads à utiliser
chunk_size = len(rainbow_table) // num_threads  # Taille de chaque partie
with ThreadPoolExecutor(max_workers=num_threads) as executor:
    futures = []
    for i in range(num_threads):
        start = i * chunk_size
        end = start + chunk_size
        if i == num_threads - 1:
            end = len(rainbow_table)
        futures.append(executor.submit(find_password, target_hash, start, end, rainbow_table))

    for future in as_completed(futures):
        password = future.result()
        if password:
            print(f"Le mot de passe correspondant est : {password}")
            password_found.set()  # Définir le drapeau sur True pour arrêter les autres threads
            break
    else:
        print("Le mot de passe n'a pas été trouvé dans la table arc-en-ciel.")