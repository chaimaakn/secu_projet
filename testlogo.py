import os
import tkinter as tk
from PIL import ImageTk, Image

# Récupérer le chemin absolu du dossier contenant le script
dossier_script = os.path.dirname(os.path.abspath(__file__))
chemin_image = os.path.join(dossier_script, "images", "HackPact.jpg") # Remplacez "votre_image.jpg" par le nom de votre image

# Créer une fenêtre
fenetre = tk.Tk()
fenetre.title("Affichage d'une image")

# Charger l'image
image = Image.open(chemin_image)
image = image.resize((400, 300), Image.LANCZOS)

# Convertir l'image en un format Tkinter-compatible
image_tk = ImageTk.PhotoImage(image)

# Créer un widget Label pour afficher l'image
label_image = tk.Label(fenetre, image=image_tk)
label_image.pack()

# Fonction pour quitter l'application
def quitter():
    fenetre.destroy()

# Bouton pour quitter l'application
bouton_quitter = tk.Button(fenetre, text="Quitter", command=quitter)
bouton_quitter.pack()

# Lancer la boucle principale de l'application
fenetre.mainloop()
