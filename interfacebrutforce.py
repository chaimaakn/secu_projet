import tkinter as tk
from tkinter import font, messagebox
import itertools
import string
import time
import hashlib

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
    while True:
        for mot in (''.join(carac) for carac in itertools.product(CARACTERES, repeat=longueur)):
            if est_bon_mot(mot, hash_a_trouver):
                end_time = time.time()  # Enregistrer le temps de fin
                temps_ecoule = end_time - start_time
                return mot, temps_ecoule
            # Mettre à jour la fenêtre principale avec chaque essai
            result_label.config(text=f" {mot}",fg="green")
            root.update()
        longueur += 1

# Fonction pour récupérer le hash MD5 entré par l'utilisateur et afficher le résultat
def recuperer_hash():
    hash_input = password_entry.get().strip()
    if len(hash_input) != 32 or not all(c in string.hexdigits for c in hash_input):
        messagebox.showerror("Erreur", "Le hash entré n'est pas valide.")
        return
    bon_mot_trouve, temps_ecoule = trouver_bon_mot(hash_input)
    if bon_mot_trouve:
        result_label.config(text=f"Le mot est: {bon_mot_trouve}\nTemps écoulé pour trouver le mot: {temps_ecoule:.6f} secondes", fg="green")
        reset_button.grid(row=4, column=0, padx=10, pady=10)
        close_button.grid(row=4, column=1, padx=10, pady=10, sticky="e")
        submit_button.grid_forget()
    else:
        result_label.config(text="Aucun mot n'a été trouvé.", fg="red")

# Fonction pour réinitialiser la recherche
def reinitialiser():
    password_entry.delete(0, tk.END)
    result_label.config(text="", fg="white")
    reset_button.grid_forget()
    close_button.grid_forget()
    submit_button.grid(row=1, column=1, padx=10, pady=10)

# Fonction pour fermer la fenêtre
def fermer_fenetre():
    root.destroy()

# Création de la fenêtre principale
root = tk.Tk()
root.title("Retrouver le mot de passe à partir d'un hash MD5")
root.configure(bg="#1E1E1E")  # Fond de fenêtre sombre

# Création des widgets
custom_font = font.Font(family="Courier", size=14, weight="bold")
password_label = tk.Label(root, text="Entrez le hash MD5 :", font=custom_font, bg="#1E1E1E", fg="white")
password_entry = tk.Entry(root, width=50, font=custom_font, bg="black", fg="white")  # Barre de saisie noire
submit_button = tk.Button(root, text="Rechercher", command=recuperer_hash, font=custom_font, bg="#008000", fg="white", width=10)  # Bouton vert
result_label = tk.Label(root, text="", font=custom_font, bg="#1E1E1E", fg="white")
reset_button = tk.Button(root, text="Réinitialiser", command=reinitialiser, font=custom_font, bg="red", fg="white", width=10)  # Bouton rouge
close_button = tk.Button(root, text="Fermer", command=fermer_fenetre, font=custom_font, bg="#FFA500", fg="white", width=10)  # Bouton orange

# Placement des widgets dans la fenêtre
password_label.grid(row=0, column=0, padx=10, pady=10)
password_entry.grid(row=0, column=1, padx=10, pady=10)
submit_button.grid(row=1, column=1, padx=10, pady=10)
result_label.grid(row=2, columnspan=2, padx=10, pady=10)

# Lancement de la boucle principale
root.mainloop()











