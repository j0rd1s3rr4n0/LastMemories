import re
import os
import subprocess
import inquirer

def validar_nombre_usuario(respuesta):
    nombre_usuario = respuesta['nuevo_nombre_usuario']
    if re.match("^[A-Za-z0-9]{4,}$", nombre_usuario):
        return True
    else:
        print("El nombre de usuario debe contener al menos 4 caracteres alfanuméricos válidos (A-Z, a-z, 0-9).")
        return False

# Obtener una lista de usuarios en el sistema
resultado = subprocess.run('net user', stdout=subprocess.PIPE, shell=True)
usuarios = re.findall(r"([A-Za-z0-9_]+)\s+", resultado.stdout.decode())

preguntas = [
    inquirer.List('nombre_usuario',
                  message='Selecciona el usuario al que deseas cambiar el nombre:',
                  choices=usuarios),
    inquirer.Text('nuevo_nombre_usuario',
                  message='Nuevo nombre de usuario:',
                  validate=validar_nombre_usuario)
]

respuestas = inquirer.prompt(preguntas)
usuario_a_cambiar = respuestas['nombre_usuario']
nuevo_nombre_usuario = respuestas['nuevo_nombre_usuario']

# Cambia el nombre de usuario en el registro de Windows
subprocess.run(['net', 'user', usuario_a_cambiar, nuevo_nombre_usuario])

print(f"Nombre de usuario de '{usuario_a_cambiar}' cambiado a '{nuevo_nombre_usuario}' en el registro de Windows.")
print("Reinicia el sistema para aplicar los cambios.")
