import os

input_folder = "input"
if not os.path.exists(input_folder):
    os.makedirs(input_folder)

sample_text = "Este es un archivo de ejemplo para encriptar usando ECC."

with open(os.path.join(input_folder, "ejemplo.txt"), "w") as file:
    file.write(sample_text)

print("Archivo de ejemplo creado en la carpeta 'input'.")