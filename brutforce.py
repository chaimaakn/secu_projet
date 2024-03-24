import itertools
import string
import time
import hashlib
import sys

# Définir les caractères autorisés
CARACTERES = string.ascii_letters + string.digits + string.punctuation

# Fonction pour calculer le hachage MD5 d'un mot
def md5(mot):
    return hashlib.md5(mot.encode()).hexdigest()

# Hachage MD5 du mot à trouver
HASH_MOT_A_TROUVER = '5a105e8b9d40e1329780d62ea2265d8a'  # bat

# Fonction pour tester si un mot correspond au hachage
def est_bon_mot(mot):
    return md5(mot) == HASH_MOT_A_TROUVER

# Fonction pour trouver le bon mot
def trouver_bon_mot():
    longueur = 1
    start_time = time.time()  # Enregistrer le temps de départ
    mots_testes = 0
    while True:
        for mot in (''.join(carac) for carac in itertools.product(CARACTERES, repeat=longueur)):
            mots_testes += 1
            if mots_testes % 10000 == 0:
                print(f"Mot testé : {mot}")
                sys.stdout.flush()  # Forcer l'affichage immédiat du message
            if est_bon_mot(mot):
                end_time = time.time()  # Enregistrer le temps de fin
                temps_ecoule = end_time - start_time
                return mot, temps_ecoule
        longueur += 1

# Exemple d'utilisation
bon_mot, temps_ecoule = trouver_bon_mot()
if bon_mot:
    print(f"\nLe mot correspondant au hachage {HASH_MOT_A_TROUVER} est: {bon_mot}")
    print(f"Temps écoulé pour trouver le mot: {temps_ecoule:.6f} secondes")
else:
    print("Aucun mot n'a été trouvé.")
