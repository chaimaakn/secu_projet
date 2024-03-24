import hashlib
import itertools
import string

# Définir les caractères autorisés
CARACTERES = string.ascii_letters + string.digits + string.punctuation

# Fonction pour calculer le hachage MD5 d'un mot
def md5(mot):
    return hashlib.md5(mot.encode()).hexdigest()

# Fonction pour réduire un hachage à une chaîne de longueur fixe
def reduction(hachage, longueur=16):
    return hachage[:longueur]

# Fonction pour créer une table arc-en-ciel
def creer_table_arc_en_ciel(longueur_chaine, longueur_reduction, nombre_chaines):
    table = {}
    for start in (''.join(carac) for carac in itertools.product(CARACTERES, repeat=longueur_chaine)):
        chaine = start
        hachage = md5(chaine)
        for _ in range(nombre_chaines):
            chaine = md5(chaine)
            hachage_reduit = reduction(hachage, longueur_reduction)
            if hachage_reduit not in table:
                table[hachage_reduit] = (start, hachage)
    return table

# Fonction pour trouver le mot de passe à partir d'un hachage donné
def trouver_mot_de_passe(hachage_cible, table_arc_en_ciel, longueur_chaine, nombre_chaines):
    hachage_reduit = reduction(hachage_cible, len(next(iter(table_arc_en_ciel))))
    if hachage_reduit in table_arc_en_ciel:
        start, hachage_final = table_arc_en_ciel[hachage_reduit]
        chaine = start
        for _ in range(nombre_chaines):
            chaine = md5(chaine)
        if md5(chaine) == hachage_cible:
            return start
    return None

# Exemple d'utilisation
longueur_chaine = 3
longueur_reduction = 8
nombre_chaines = 10000

table_arc_en_ciel = creer_table_arc_en_ciel(longueur_chaine, longueur_reduction, nombre_chaines)

hachage_cible = md5('mot_de_passe')
mot_de_passe = trouver_mot_de_passe(hachage_cible, table_arc_en_ciel, longueur_chaine, nombre_chaines)

if mot_de_passe:
    print(f"Le mot de passe correspondant au hachage {hachage_cible} est: {mot_de_passe}")
else:
    print("Impossible de trouver le mot de passe.")