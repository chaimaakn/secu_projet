import tkinter as tk
from tkinter import font
import hashlib

def submit_password():
    hashed_password = password_entry.get()
    with open(file_name, 'r') as file_to_check:
        for line in file_to_check:
            word = line.strip()
            md5_returned = hashlib.md5(word.encode()).hexdigest()
            if hashed_password == md5_returned:
                result_label.config(text=f"Le mot de passe est {word}", fg="green", font=custom_font)
                return
        result_label.config(text="Mot de passe non trouvé. Changez de dictionnaire.", fg="red", font=custom_font)

# Création de la fenêtre principale
root = tk.Tk()
root.title("Déchiffrement de mot de passe")
root.configure(bg="#212121")

# Création d'un cadre pour contenir tous les éléments
main_frame = tk.Frame(root, bg="#212121")  
main_frame.pack(padx=20, pady=20)

# Création du champ de saisie pour le mot de passe hashé
custom_font = font.Font(family="Helvetica", size=14, weight="bold")
password_label = tk.Label(main_frame, text="Mot de passe hashé :", font=custom_font, bg="#212121", fg="white")
password_label.grid(row=0, column=0, sticky="w", padx=(0, 10))

password_entry = tk.Entry(main_frame, width=50, bg="#212121", fg="white", font=custom_font)
password_entry.grid(row=0, column=1, sticky="w")
password_entry.configure(insertbackground="white")  # Changement de la couleur du curseur

# Création du bouton de soumission
submit_font = font.Font(weight="bold")
submit_button = tk.Button(main_frame, text="Soumettre", command=submit_password, bg="green", font=submit_font, width=10)
submit_button.grid(row=1, column=1, sticky="w", pady=10)

# Étiquette pour afficher le résultat
result_label = tk.Label(main_frame, text="", bg="#212121", font=custom_font)
result_label.grid(row=2, column=0, columnspan=2, pady=10)

file_name = "mots.txt"  # Nom du fichier contenant le dictionnaire

# Lancement de la boucle principale
root.mainloop()
