'''''
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
HASH_MOT_A_TROUVER = '5f3f4681121b460e3304a1887f42f1c3'  # bat

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
'''
'''''
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

# Fonction pour tester si un mot correspond au hachage
def est_bon_mot(mot, hash_a_trouver):
    return md5(mot) == hash_a_trouver

# Fonction pour trouver le bon mot
def trouver_bon_mot(hash_a_trouver):
    longueur = 1
    start_time = time.time()  # Enregistrer le temps de départ
    mots_testes = 0
    while True:
        for mot in (''.join(carac) for carac in itertools.product(CARACTERES, repeat=longueur)):
            mots_testes += 1
            if mots_testes % 10000 == 0:
                print(f"Mots testés : {mots_testes}")
                sys.stdout.flush()  # Forcer l'affichage immédiat du message
            if est_bon_mot(mot, hash_a_trouver):
                end_time = time.time()  # Enregistrer le temps de fin
                temps_ecoule = end_time - start_time
                return mot, temps_ecoule
        longueur += 1

# Fonction pour permettre à l'utilisateur d'entrer un hash et récupérer le mot correspondant
def retrouver_mot():
    hash_input = input("Entrez le hash MD5 : ").strip()
    if len(hash_input) != 32 or not all(c in string.hexdigits for c in hash_input):
        print("Le hash entré n'est pas valide.")
        return
    bon_mot_trouve, temps_ecoule = trouver_bon_mot(hash_input)
    if bon_mot_trouve:
        print(f"\nLe mot correspondant au hachage {hash_input} est: {bon_mot_trouve}")
        print(f"Temps écoulé pour trouver le mot: {temps_ecoule:.6f} secondes")
    else:
        print("Aucun mot n'a été trouvé.")

# Exemple d'utilisation
retrouver_mot()
'''
''''
import itertools
import string
import time
import hashlib
import sys
import multiprocessing

# Définir les caractères autorisés
CARACTERES = string.ascii_letters + string.digits + string.punctuation

# Fonction pour calculer le hachage MD5 d'un mot
def md5(mot):
    return hashlib.md5(mot.encode()).hexdigest()

# Fonction pour tester si un mot correspond au hachage
def est_bon_mot(mot, hash_a_trouver):
    return md5(mot) == hash_a_trouver

# Fonction pour trouver le bon mot en parallèle
def trouver_bon_mot_parallele(hash_a_trouver, longueur, resultats):
    for mot in (''.join(carac) for carac in itertools.product(CARACTERES, repeat=longueur)):
        if est_bon_mot(mot, hash_a_trouver):
            resultats.append(mot)
            return

# Fonction pour trouver le bon mot
def trouver_bon_mot(hash_a_trouver):
    longueur = 1
    start_time = time.time()
    mots_testes = 0

    while True:
        resultats = []
        with multiprocessing.Pool() as pool:
            for _ in range(multiprocessing.cpu_count()):
                pool.apply_async(trouver_bon_mot_parallele, args=(hash_a_trouver, longueur, resultats))
            pool.close()
            pool.join()

        if resultats:
            end_time = time.time()
            temps_ecoule = end_time - start_time
            return resultats[0], temps_ecoule

        longueur += 1
        mots_testes += 10000
        print(f"Mots testés : {mots_testes}")
        sys.stdout.flush()

# Fonction pour permettre à l'utilisateur d'entrer un hash et récupérer le mot correspondant
def retrouver_mot():
    hash_input = input("Entrez le hash MD5 : ").strip()
    if len(hash_input) != 32 or not all(c in string.hexdigits for c in hash_input):
        print("Le hash entré n'est pas valide.")
        return

    bon_mot_trouve, temps_ecoule = trouver_bon_mot(hash_input)
    if bon_mot_trouve:
        print(f"\nLe mot correspondant au hachage {hash_input} est: {bon_mot_trouve}")
        print(f"Temps écoulé pour trouver le mot: {temps_ecoule:.6f} secondes")
    else:
        print("Aucun mot n'a été trouvé.")

if __name__ == '__main__':
    retrouver_mot()
    '''
import itertools
import string
import time
import passlib.hash
import sys

# Définir les caractères autorisés
CARACTERES = string.ascii_letters + string.digits + string.punctuation

# Fonction pour calculer le hachage MD5 d'un mot
def md5(mot):
    return passlib.hash.md5_crypt.hash(mot)

# Fonction pour tester si un mot correspond au hachage
def est_bon_mot(mot, hash_a_trouver):
    return passlib.hash.md5_crypt.verify(mot, hash_a_trouver)

# Fonction pour trouver le bon mot
def trouver_bon_mot(hash_a_trouver):
    longueur = 1
    start_time = time.time()  # Enregistrer le temps de départ
    mots_testes = 0
    while True:
        for mot in (''.join(carac) for carac in itertools.product(CARACTERES, repeat=longueur)):
            mots_testes += 1
            if mots_testes % 10000 == 0:
                print(f"Mot testé : {mot}")
                sys.stdout.flush()  # Forcer l'affichage immédiat du message
            if est_bon_mot(mot, hash_a_trouver):
                end_time = time.time()  # Enregistrer le temps de fin
                temps_ecoule = end_time - start_time
                return mot, temps_ecoule
        longueur += 1
        # Si aucun mot n'est trouvé après avoir parcouru toutes les longueurs possibles, retourner None
        if longueur > 50:  # Limite de longueur arbitraire pour éviter une recherche indéfinie
            return None, None

# Fonction pour permettre à l'utilisateur d'entrer un hash et récupérer le mot correspondant
def retrouver_mot():
    hash_input = "$$1$amZNTQGA$IdIS0M5KJxAp2gRT7oDBh0"# attention hada twilllllllll syo wa7d 9sir
   # if len(hash_input) != 32 or not all(c in string.hexdigits for c in hash_input):
    #    print("Le hash entré n'est pas valide.")
     #   return
    bon_mot_trouve, temps_ecoule = trouver_bon_mot(hash_input)
    if bon_mot_trouve is not None:
        print(f"\nLe mot correspondant au hachage {hash_input} est: {bon_mot_trouve}")
        print(f"Temps écoulé pour trouver le mot: {temps_ecoule:.6f} secondes")
    else:
        print("Aucun mot n'a été trouvé.")

# Appel de la fonction pour retrouver un mot à partir d'un hash
retrouver_mot()

''''''