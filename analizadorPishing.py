import tkinter as tk
from tkinter import scrolledtext
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import socket
import concurrent.futures
import ipaddress
import dns.resolver
import numpy as np
import joblib
from collections import Counter


# Carga del modelo entrenado
modelo_path = 'Modelos/ModeloSVC.sav'
loaded_model_RF = joblib.load(modelo_path)


# Función para verificar si un puerto específico está abierto en un host dado
def check_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            return result == 0
    except (socket.gaierror, socket.error) as e:
        print(f"Error al verificar el puerto {port} en el host {host}: {e}")
    return False

# Función para recolectar varias características de una URL dada
def recolectar_datos_sitioweb(url):
    # Inicializar diccionario para almacenar las características de la URL
    caracteristicas = {
        "IP_Address": None,
        "URL_longitud": None,
        "URL_corto": None,
        "URL_arroba": None,
        "URL_slash": None,
        "URL_linea": None,
        "URL_puntos": None,
        "HTTPS_SSL": None,
        "Domain_registro": None,
        "Favicon": None,
        "Puertos": None,
        "Domain_https": None,
        "Request_URL": None,
        "URL_ancla": None,
        "Tags": None,
        "Registro_DNS": None,
        "SFH": None,
        "Submit_email": None,
        "Abnormal_URL": None,
        "Forwarding": None,
        "Pop_up": None,
        "IFrame": None,
        "Edad_dominio": None,
        "tipoUrl": 0}

    # Verificar si la URL es una dirección IP
    try:
        ipaddress.ip_address(url)
        caracteristicas["IP_Address"] = -1
    except ValueError:
        caracteristicas["IP_Address"] = 1

    # Longitud de la URL
    url_longitud = len(url)
    caracteristicas["URL_longitud"] = 1 if url_longitud < 54 else (-1 if url_longitud >= 75 else 0)

    # Verificar si la URL usa un servicio de acortamiento
    try:
        response = requests.get(url, timeout=1)
        response.raise_for_status()
        html_content = response.text
        caracteristicas["URL_corto"] = -1 if any(short_url in html_content for short_url in ['bit.ly', 'goo.gl', 't.co']) else 1
    except requests.RequestException:
        caracteristicas["URL_corto"] = 0

    # Verificar si la URL contiene un "@"
    caracteristicas["URL_arroba"] = -1 if "@" in url else 1

    # Verificar si la URL tiene más de un "//" después del protocolo (http o https)
    caracteristicas["URL_slash"] = -1 if url[7:].count("//") > 1 else 1

    # Verificar si la URL contiene un guion "-"
    caracteristicas["URL_linea"] = -1 if "-" in url else 1

    # Contar el número de puntos en la URL
    puntos = url.count(".")
    caracteristicas["URL_puntos"] = 1 if puntos <= 3 else (0 if puntos == 4 else -1)

    # Verificar el estado del SSL
    try:
        response = requests.get(url, timeout=1, verify=True)
        caracteristicas["HTTPS_SSL"] = 1 if response.status_code == 200 and response.url.startswith("https://") else -1
    except requests.RequestException:
        caracteristicas["HTTPS_SSL"] = -1

    # Verificar el tiempo de registro del dominio
    try:
        whois_info = whois.whois(url)
        fecha_creacion = whois_info.creation_date
        if isinstance(fecha_creacion, list):
            fecha_creacion = fecha_creacion[0]
        if fecha_creacion:
            tiempo_registro = datetime.now() - fecha_creacion
            caracteristicas["Domain_registro"] = 1 if tiempo_registro.days > 365 else -1
        else:
            caracteristicas["Domain_registro"] = 0
    except whois.parser.PywhoisError:
        caracteristicas["Domain_registro"] = 0

    # Verificar si la URL tiene un favicon
    try:
        response = requests.get(url, timeout=1)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        favicon_link = soup.find('link', rel='shortcut icon')
        caracteristicas["Favicon"] = 1 if favicon_link and favicon_link['href'].startswith(url) else -1
    except requests.RequestException:
        caracteristicas["Favicon"] = 0

    # Verificar los puertos abiertos en el host de la URL
    try:
        host = socket.gethostbyname(url.split("//")[-1].split("/")[0])
        open_ports = set()
        # Utilizar un ThreadPoolExecutor para verificar los puertos en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_port = {executor.submit(check_port, host, port): port for port in [21, 25, 80, 443, 3389]}
            for future in concurrent.futures.as_completed(future_to_port):
                if future.result():
                    open_ports.add(future_to_port[future])
        caracteristicas["Puertos"] = 1 if not open_ports else -1
    except:
        caracteristicas["Puertos"] = 0

    # Verificar si la URL usa HTTPS
    caracteristicas["Domain_https"] = 1 if url.startswith("https://") else -1

    # Verificar el porcentaje de URLs externas en la página
    try:
        response = requests.get(url, timeout=1)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        all_urls = [tag['src'] for tag in soup.find_all(['img', 'script', 'link'], src=True)]
        if all_urls:
            same_domain_urls = [u for u in all_urls if '//' in u and url.split('//')[1].split('/')[0] in u.split('//')[1].split('/')[0]]
            external_requests_percentage = (len(all_urls) - len(same_domain_urls)) / len(all_urls * 100)
            caracteristicas["Request_URL"] = 1 if external_requests_percentage < 22 else (0 if external_requests_percentage <= 61 else -1)
        else:
            caracteristicas["Request_URL"] = 0
    except requests.RequestException:
        caracteristicas["Request_URL"] = 0


    # Verificar el porcentaje de enlaces vacíos en la página
    try:
        response = requests.get(url, timeout=1)
        soup = BeautifulSoup(response.content, 'html.parser')
        all_anchors = [tag['href'] for tag in soup.find_all('a', href=True)]
        empty_anchors = [a for a in all_anchors if a == "#" or a.lower() in ["", "#", "javascript:void(0)"]]
        empty_anchors_percentage = (len(empty_anchors) / len(all_anchors)) * 100
        caracteristicas["URL_ancla"] = 1 if empty_anchors_percentage < 31 else (0 if empty_anchors_percentage <= 67 else -1)
    except:
        caracteristicas["URL_ancla"] = 0

    # Verificar la presencia de meta tags
    try:
        response = requests.get(url, timeout=1)
        soup = BeautifulSoup(response.content, 'html.parser')
        meta_tags = [tag['content'] for tag in soup.find_all('meta', attrs={'http-equiv': 'refresh'})]
        caracteristicas["Tags"] = -1 if meta_tags else 1
    except:
        caracteristicas["Tags"] = 0

        # Verificar el registro DNS del dominio
    try:
        registros_dns = dns.resolver.resolve(url, 'A')
        caracteristicas["Registro_DNS"] = 1 if registros_dns else -1
    except:
        caracteristicas["Registro_DNS"] = 0

    # Verificar la seguridad del formulario de envío (SFH)
    try:
        response = requests.get(url, timeout=1)
        forms = BeautifulSoup(response.content, 'html.parser').find_all('form')
        sfh_untrustworthy = any(form.get('action') in ["", "about:blank"] or form.get('action') and not form.get('action').startswith("https://") for form in forms)
        caracteristicas["SFH"] = -1 if sfh_untrustworthy else 1
    except:
        caracteristicas["SFH"] = 0

    # Verificar si la página contiene direcciones de correo "mailto:"
    try:
        response = requests.get(url, timeout=1)
        caracteristicas["Submit_email"] = -1 if "mailto:" in response.text else 1
    except:
        caracteristicas["Submit_email"] = 0
    # Verificar si la URL es anormal
    try:
        whois_info = whois.whois(url)
        caracteristicas["Abnormal_URL"] = 1 if whois_info.domain_name else -1
    except:
        caracteristicas["Abnormal_URL"] = 0

    # Verificar si hay redireccionamientos excesivos
    try:
        response = requests.get(url, timeout=1, allow_redirects=True)
        redirects = len(response.history)
        caracteristicas["Forwarding"] = 1 if redirects <= 1 else (0 if redirects <= 4 else -1)
    except:
        caracteristicas["Forwarding"] = 0

    # Verificar si hay ventanas emergentes (pop-ups)
    try:
        response = requests.get(url, timeout=1)
        caracteristicas["Pop_up"] = -1 if "window.open(" in response.text.lower() else 1
    except:
        caracteristicas["Pop_up"] = 0

    # Verificar el uso de iFrames
    try:
        response = requests.get(url, timeout=1)
        caracteristicas["IFrame"] = -1 if "<iframe" in response.text.lower() else 1
    except:
        caracteristicas["IFrame"] = 0

    # Verificar la edad del dominio
    try:
        whois_info = whois.whois(url)
        fecha_actualizacion = whois_info.updated_date
        if isinstance(fecha_actualizacion, list):
            fecha_actualizacion = fecha_actualizacion[0]
        if fecha_actualizacion:
            edad_dominio = (datetime.now() - fecha_actualizacion).days
            caracteristicas["Edad_dominio"] = 1 if edad_dominio >= 183 else -1
        else:
            caracteristicas["Edad_dominio"] = 0
    except:
        caracteristicas["Edad_dominio"] = 0

    return caracteristicas


def predecir_data(dataPredecir):
    resultados = []
    for _ in range(10):
        dataP = np.append([dataPredecir], [[]], axis=1)
        prediccion = loaded_model_RF.predict(dataP[:, 0:23])
        if prediccion[0] == 1:
            resultados.append("LEGÍTIMO")
        else:
            resultados.append("PHISHING")

    # Contar las predicciones y obtener la más común
    conteo_resultados = Counter(resultados)
    resultado_final = conteo_resultados.most_common(1)[0][0]

    salida = f"El sitio web es {resultado_final}"
    return salida


def ejecutar_analisis():
    url = entry_url.get()
    if url:
        resultados = recolectar_datos_sitioweb(url)
        result_text.delete(1.0, tk.END)

        # Convertir resultados a la forma esperada por predecir_data
        dataPredecir = list(resultados.values())  # Ajusta según la estructura de resultados
        prediction_result = predecir_data(dataPredecir)

        # Mostrar el resultado de la predicción
        result_text.insert(tk.END, f"Resultado de la predicción: {prediction_result}\n")


# Crear la interfaz gráfica
root = tk.Tk()
root.title("Analizador de URLs")

# Crear el campo de entrada para la URL
label_url = tk.Label(root, text="Ingrese la URL:")
label_url.pack()
entry_url = tk.Entry(root, width=50)
entry_url.pack()

# Crear el botón para analizar la URL
button_analizar = tk.Button(root, text="Analizar", command=ejecutar_analisis)
button_analizar.pack()

# Crear el campo de texto para mostrar los resultados
result_text = scrolledtext.ScrolledText(root, width=60, height=20)
result_text.pack()

# Iniciar el bucle principal de la interfaz
root.mainloop()
