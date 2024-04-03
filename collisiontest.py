import hashlib

# Fonction pour calculer le hachage MD5 d'un mot
def md5(mot):
    return hashlib.md5(mot.encode()).hexdigest()

# Fonction de réduction
def reduction(hachage, longueur=8):
    return hachage[:longueur]

# Fonction pour générer les 100 chaînes à partir d'un mot donné
def generer_chaines(mot):
    chaines = []
    hachage_courant = md5(mot)
    for _ in range(100):
        chaines.append(hachage_courant)
        hachage_courant = md5(reduction(hachage_courant))
    return chaines

# Mot à utiliser pour générer les chaînes
mot_initial = "winomstyle"

# Générer les chaînes à partir du mot initial
chaines = generer_chaines(mot_initial)

# Écrire les chaînes dans un fichier texte
with open("chaines.txt", "w") as f:
    for chaine in chaines:
        f.write(chaine + "\n")

print("Les 100 chaînes ont été écrites dans le fichier 'chaines.txt'.")
