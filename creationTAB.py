import hashlib

# Fonction de réduction pour réduire un hachage à une longueur fixe
def reduction(hachage, longueur=8):
    return hachage[:longueur]

# Fonction pour calculer le hachage MD5 d'un mot
def md5(mot):
    return hashlib.md5(mot.encode()).hexdigest()

# Fonction pour créer une table arc-en-ciel à partir d'un dictionnaire de mots de passe
def creer_table_arc_en_ciel(dictionnaire, longueur_chaine, longueur_reduction, nombre_chaines):
    table = {}
    for mot in dictionnaire:
        chaine = mot
        for _ in range(nombre_chaines):
            hachage = md5(chaine)
            chaine = reduction(hachage, longueur_reduction)
        table[mot] = hachage
    return table

# Charger le dictionnaire de mots de passe depuis un fichier
def charger_dictionnaire(file_name):
    with open(file_name, 'r') as file:
        return [mot.strip() for mot in file.readlines()]

# Paramètres pour la création de la table arc-en-ciel
longueur_chaine = 3
longueur_reduction = 8
nombre_chaines = 100

# Nom du fichier de dictionnaire
nom_fichier_dictionnaire = "liste.txt"

# Charger le dictionnaire depuis le fichier
dictionnaire = charger_dictionnaire(nom_fichier_dictionnaire)

# Créer la table arc-en-ciel
table_arc_en_ciel = creer_table_arc_en_ciel(dictionnaire, longueur_chaine, longueur_reduction, nombre_chaines)

# Écrire la table arc-en-ciel dans un fichier texte
nom_fichier_table_arc_en_ciel = "table_arc_en_ciel.txt"
with open(nom_fichier_table_arc_en_ciel, 'w') as file:
    for mot_initial, hachage in table_arc_en_ciel.items():
        file.write(f"{mot_initial} {hachage}\n")

print(f"La table arc-en-ciel a été créée avec succès et enregistrée dans '{nom_fichier_table_arc_en_ciel}'.")