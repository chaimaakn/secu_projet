import hashlib
import itertools

def generate_hash(password):
    """Génère un hash SHA-256 pour un mot de passe donné."""
    return hashlib.sha256(password.encode()).hexdigest()

def load_password_list(filename):
    """Charge la liste des mots de passe depuis un fichier."""
    with open(filename, 'r') as file:
        return [line.strip() for line in file]

def apply_transformations(base_password):
    """Applique différentes transformations sur un mot de base."""
    transformations = [
        base_password,
        base_password.upper(),
        base_password.lower(),
        base_password.capitalize(),
        base_password + "123",
        base_password + "!",
        "123" + base_password,
        "!"+ base_password,
    ]
    return transformations

def brute_force_extension(base_password, charset, max_length=2):
    """Génère des extensions de force brute pour un mot de base."""
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            yield base_password + ''.join(combo)

def hybrid_attack(target_hash, filename, charset="0123456789!@#"):
    """Effectue une attaque hybride sur le hash cible."""
    password_list = load_password_list(filename)
    for base_password in password_list:
        # Appliquer les transformations simples
        transformations = apply_transformations(base_password)
        for password in transformations:
            if generate_hash(password) == target_hash:
                print(f"Mot de passe trouvé : {password}")
                return password

        # Appliquer la force brute avec extensions sur chaque transformation
        for password in transformations:
            for extended_password in brute_force_extension(password, charset):
                if generate_hash(extended_password) == target_hash:
                    print(f"Mot de passe trouvé avec extension : {extended_password}")
                    return extended_password

    print("Aucun mot de passe correspondant trouvé.")
    return None

# Exemple d'utilisation
target_password = "secret123!!!"
target_hash = generate_hash(target_password)  # Simuler un hash cible
filename = 'liste.txt'  # Nom du fichier contenant les mots de base

found_password = hybrid_attack(target_hash, filename)