import tkinter as tk
from tkinter import ttk, messagebox, font
from tqdm import tqdm
from tkmacosx import Button
import hashlib
import time
from datetime import datetime

# Couleurs
BG_COLOR = "#000000"
FG_COLOR = "#00ff00"
ACCENT_COLOR = "#ff0000"
PROGRESS_COLOR = "#00ff00"
BUTTON_COLOR = "#000000"  # Couleur des boutons
BUTTON_ACTIVE_COLOR = "#004400"  # Couleur des boutons lorsqu'ils sont actifs

# Police de caractères
FONT_FAMILY = "Courier"
FONT_SIZE = 12

# Fonction pour faire clignoter les points
def blink_dots(label, delay=500):
    def show_dots(dots):
        label.config(text="Patienter" + dots)
        label.after(delay, show_dots, dots[1:] + dots[:1])

    show_dots("...")

# Fonction pour afficher l'interface de l'attaque par dictionnaire
def show_dictionary_attack():
    # Masquer les boutons principaux
    attack_buttons_frame.place_forget()

    # Afficher l'interface de l'attaque par dictionnaire
    label_hashed_password.place(relx=0.5, rely=0.35, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    entry_hashed_password.place(relx=0.5, rely=0.4, anchor='center')  # Centrer en hauteur
    crack_button.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le bas

# Fonction pour cracker le mot de passe
def crack_password():
    hashed_password = entry_hashed_password.get().strip()
    if not hashed_password:
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return

    # Cacher tous les widgets sauf la barre de progression et le label clignotant
    label_hashed_password.place_forget()
    entry_hashed_password.place_forget()
    crack_button.place_forget()
    result_frame.place_forget()

    with open("mots.txt", "r") as file:
        words = [line.strip() for line in file]

    progress_bar.config(maximum=100)
    progress_bar.place(relx=0.5, rely=0.35, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    percentage_label.place(relx=0.5, rely=0.3, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    blink_label.place(relx=0.5, rely=0.45, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le bas
    blink_dots(blink_label)  # Démarrer le clignotement des points

    for progress in tqdm(range(101), desc="Chercher...", unit="%", leave=False):
        progress_bar.step(1)
        percentage_label.config(text=f"{progress}%")
        root.update()
        time.sleep(0.05)

    progress_bar.stop()
    progress_bar.place_forget()  # Cacher la barre de progression
    percentage_label.place_forget()  # Cacher le label de pourcentage
    blink_label.place_forget()  # Cacher le label clignotant

    for word in words:
        md5_hash = hashlib.md5(word.encode()).hexdigest()
        if hashed_password == md5_hash:
            result_label.config(text=f"Le mot de passe est :", fg=FG_COLOR)
            password_label.config(text=word, fg=ACCENT_COLOR)
            result_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
            return

    result_label.config(text="Tentative échouée", fg=ACCENT_COLOR)
    password_label.config(text="")
    result_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur

# Fonction pour réinitialiser l'interface
def retry():
    # Cacher les éléments de la tentative précédente
    result_frame.place_forget()
    result_label.config(text="")
    password_label.config(text="")

    # Réinitialiser l'interface de l'attaque par dictionnaire
    show_dictionary_attack()

# Obtenir la date et l'heure actuelles
def get_current_datetime():
    now = datetime.now()
    date_time = now.strftime("%d/%m/%Y %H:%M:%S")
    return date_time

# Configuration de la fenêtre principale
root = tk.Tk()
root.title("Attaque par dictionnaire")
root.configure(bg=BG_COLOR)
root.geometry("500x400")  # Définir la taille de la fenêtre

# Obtenir les dimensions de la fenêtre
window_width = root.winfo_reqwidth()
window_height = root.winfo_reqheight()

# Calculer les coordonnées pour centrer la fenêtre
position_right = int(root.winfo_screenwidth()/2 - window_width/2)
position_down = int(root.winfo_screenheight()/2 - window_height/2)

# Définir la position de la fenêtre au milieu de l'écran
root.geometry("+{}+{}".format(position_right, position_down))

# Police personnalisée
custom_font = font.Font(family=FONT_FAMILY, size=FONT_SIZE)

# Frame pour les boutons d'attaque
attack_buttons_frame = tk.Frame(root, bg=BG_COLOR)
attack_buttons_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur

# Boutons pour les différentes attaques
attack_dictionary_button = Button(attack_buttons_frame, text="Attaque par dictionnaire", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR, command=show_dictionary_attack)
attack_dictionary_button.pack(pady=10)

brute_force_button = Button(attack_buttons_frame, text="Brute Force", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR)
brute_force_button.pack(pady=10)

rainbow_attack_button = Button(attack_buttons_frame, text="Rainbow Attack", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR)
rainbow_attack_button.pack(pady=10)

lookup_table_button = Button(attack_buttons_frame, text="Lookup Table", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR)
lookup_table_button.pack(pady=10)

# Label pour le mot de passe haché
label_hashed_password = tk.Label(root, text="Entrez le mot de passe haché (MD5) :", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)

# Entrée pour le mot de passe haché
entry_hashed_password = tk.Entry(root, width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)

# Bouton pour cracker le mot de passe
crack_button = Button(root, text="Cracker le mot de passe", command=crack_password, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)

# Barre de progression
progress_bar = ttk.Progressbar(root, length=400, mode="determinate", style="Custom.Horizontal.TProgressbar")

# Label pour afficher le pourcentage
percentage_label = tk.Label(root, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)

# Label clignotant
blink_label = tk.Label(root, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)

# Frame pour afficher le résultat et le bouton "Nouvelle tentative"
result_frame = tk.Frame(root, bg=BG_COLOR)
result_label = tk.Label(result_frame, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)
result_label.pack(side=tk.LEFT, padx=10)
password_label = tk.Label(result_frame, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
password_label.pack(side=tk.LEFT)
retry_button = Button(result_frame, text="Nouvelle tentative", command=retry, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
retry_button.pack(side=tk.LEFT, padx=10)

# Label pour afficher la date et l'heure en haut à droite
date_label = tk.Label(root, text=get_current_datetime(), fg="#00FF00", bg=BG_COLOR, font=("Courier", 12))
date_label.place(relx=1.0, rely=0, anchor='ne')

# Bouton "Retour" en bas à gauche
back_button = Button(root, text="Retour", command=root.destroy, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR)
back_button.place(relx=0, rely=1.0, anchor='sw')

# Style personnalisé pour la barre de progression
style = ttk.Style()
style.theme_use("default")
style.configure("Custom.Horizontal.TProgressbar", troughcolor=BG_COLOR, bordercolor=PROGRESS_COLOR, background=PROGRESS_COLOR, borderwidth=2)

root.mainloop()