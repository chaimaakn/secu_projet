import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, font
from tqdm import tqdm
import time
from tkmacosx import Button

# Couleurs
BG_COLOR = "#000000"
FG_COLOR = "#00ff00"
ACCENT_COLOR = "#ff0000"
PROGRESS_COLOR = "#00ff00"
BUTTON_COLOR = "#000000"  # Couleur des boutons

# Police de caractères
FONT_FAMILY = "Courier"
FONT_SIZE = 12

# Fonction pour faire clignoter les points
def blink_dots(label, delay=500):
    def show_dots(dots):
        label.config(text="Patienter" + dots)
        label.after(delay, show_dots, dots[1:] + dots[:1])

    show_dots("...")

# Fonction pour cracker le mot de passe
def crack_password():
    hashed_password = entry_hashed_password.get().strip()
    if not hashed_password:
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return

    # Cacher tous les widgets sauf la barre de progression et le label clignotant
    label_hashed_password.pack_forget()
    entry_hashed_password.pack_forget()
    crack_button.pack_forget()
    result_frame.pack_forget()

    with open("mots.txt", "r") as file:
        words = [line.strip() for line in file]

    progress_bar.config(maximum=100)
    progress_bar.pack(pady=10)
    percentage_label.pack(side=tk.TOP)
    blink_label.pack(pady=5)  # Afficher le label clignotant en dessous
    blink_dots(blink_label)  # Démarrer le clignotement des points

    for progress in tqdm(range(101), desc="Chercher...", unit="%", leave=False):
        progress_bar.step(1)
        percentage_label.config(text=f"{progress}%")
        root.update()
        time.sleep(0.05)

    progress_bar.stop()
    progress_bar.pack_forget()  # Cacher la barre de progression
    percentage_label.pack_forget()  # Cacher le label de pourcentage
    blink_label.pack_forget()  # Cacher le label clignotant

    for word in words:
        md5_hash = hashlib.md5(word.encode()).hexdigest()
        if hashed_password == md5_hash:
            result_label.config(text=f"Le mot de passe est :", fg=FG_COLOR)
            password_label.config(text=word, fg=ACCENT_COLOR)
            result_frame.pack(pady=10)
            return

    result_label.config(text="Tentative échouée", fg=ACCENT_COLOR)
    password_label.config(text="")
    result_frame.pack(pady=10)

# Fonction pour réinitialiser l'interface
def retry():
    # Cacher tous les widgets
    label_hashed_password.pack_forget()
    entry_hashed_password.pack_forget()
    crack_button.pack_forget()
    result_frame.pack_forget()
    blink_label.pack_forget()  # Cacher le label clignotant
    percentage_label.pack_forget()  # Cacher le label de pourcentage

    # Réafficher les widgets initiaux
    label_hashed_password.pack(pady=10)
    entry_hashed_password.pack()
    crack_button.pack(pady=10)

# Configuration de la fenêtre principale
root = tk.Tk()
root.title("Attaque par dictionnaire")
root.configure(bg=BG_COLOR)

root.config(highlightbackground="#00ff00", highlightcolor="#00ff00", highlightthickness=0.5)

# Police personnalisée
custom_font = font.Font(family=FONT_FAMILY, size=FONT_SIZE)

# Label pour le mot de passe haché
label_hashed_password = tk.Label(root, text="Entrez le mot de passe haché (MD5) :", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
label_hashed_password.pack(pady=10)

# Entrée pour le mot de passe haché
entry_hashed_password = tk.Entry(root, width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)
entry_hashed_password.pack()

# Barre de progression
progress_bar = ttk.Progressbar(root, length=400, mode="determinate", style="Custom.Horizontal.TProgressbar")

# Label pour afficher le pourcentage
percentage_label = tk.Label(root, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)

# Label clignotant
blink_label = tk.Label(root, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)

# Bouton pour cracker le mot de passe
crack_button = Button(root, text="Cracker le mot de passe", command=crack_password, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
crack_button.pack(pady=10)

# Frame pour afficher le résultat et le bouton "Nouvelle tentative"
result_frame = tk.Frame(root, bg=BG_COLOR)
result_label = tk.Label(result_frame, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)
result_label.pack(side=tk.LEFT, padx=10)
password_label = tk.Label(result_frame, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
password_label.pack(side=tk.LEFT)
retry_button = Button(result_frame, text="Nouvelle tentative", command=retry, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
retry_button.pack(side=tk.LEFT, padx=10)

# Style personnalisé pour la barre de progression
style = ttk.Style()
style.theme_use("default")
style.configure("Custom.Horizontal.TProgressbar", troughcolor=BG_COLOR, bordercolor=PROGRESS_COLOR, background=PROGRESS_COLOR, borderwidth=2)

root.mainloop()
