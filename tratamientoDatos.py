import os
import re
from bs4 import BeautifulSoup
import socket
import requests
import csv
from datetime import datetime
import whois
import concurrent.futures
import ipaddress
import dns.resolver
import pandas as pd

def cargar_csv_a_lista(file_path, delimiter=';'):
    if not os.path.isfile(file_path):
        print(f"Error: El archivo {file_path} no existe.")
        return []

    try:
        df = pd.read_csv(file_path, delimiter=delimiter, on_bad_lines='skip')
        data_list = df.values.tolist()
        return data_list
    except Exception as e:
        print(f"Error al cargar el archivo CSV {file_path}: {e}")
        return []

def check_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            return result == 0
    except (socket.gaierror, socket.error) as e:
        print(f"Error al verificar el puerto {port} en el host {host}: {e}")
    return False

def recolectar_datos_sitioweb(url, session):
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
        "Domain_edad": None,
        "Registro_DNS": None,
        "tipoUrl": None
    }

    try:
        ipaddress.ip_address(url)
        caracteristicas["IP_Address"] = -1
    except ValueError:
        caracteristicas["IP_Address"] = 1

    url_longitud = len(url)
    caracteristicas["URL_longitud"] = 1 if url_longitud < 54 else (-1 if url_longitud >= 75 else 0)

    try:
        response = session.get(url, timeout=1)
        response.raise_for_status()
        html_content = response.text
        caracteristicas["URL_corto"] = -1 if any(short_url in html_content for short_url in ['bit.ly', 'goo.gl', 't.co']) else 1
    except requests.RequestException:
        caracteristicas["URL_corto"] = 0

    caracteristicas["URL_arroba"] = -1 if "@" in url else 1
    caracteristicas["URL_slash"] = -1 if url[7:].count("//") > 1 else 1
    caracteristicas["URL_linea"] = -1 if "-" in url else 1

    puntos = url.count(".")
    caracteristicas["URL_puntos"] = 1 if puntos <= 3 else (0 if puntos == 4 else -1)

    try:
        response = session.get(url, timeout=1, verify=True)
        caracteristicas["HTTPS_SSL"] = 1 if response.status_code == 200 and response.url.startswith("https://") else -1
    except requests.exceptions.RequestException:
        caracteristicas["HTTPS_SSL"] = -1

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

    try:
        response = session.get(url, timeout=1)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        favicon_link = soup.find('link', rel='shortcut icon')
        caracteristicas["Favicon"] = 1 if favicon_link and favicon_link['href'].startswith(url) else -1
    except requests.RequestException:
        caracteristicas["Favicon"] = 0

    try:
        host = socket.gethostbyname(url.split("//")[-1].split("/")[0])
        open_ports = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_port = {executor.submit(check_port, host, port): port for port in [21, 25, 80, 443, 3389]}
            for future in concurrent.futures.as_completed(future_to_port):
                if future.result():
                    open_ports.add(future_to_port[future])
        caracteristicas["Puertos"] = 1 if not open_ports else -1
    except:
        caracteristicas["Puertos"] = 0

    caracteristicas["Domain_https"] = 1 if url.startswith("https://") else -1

    try:
        response = session.get(url, timeout=1)
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

    try:
        response = session.get(url, timeout=1)
        soup = BeautifulSoup(response.content, 'html.parser')
        all_anchors = [tag['href'] for tag in soup.find_all('a', href=True)]
        empty_anchors = [a for a in all_anchors if a == "#" or a.lower() in ["", "#", "javascript:void(0)"]]
        empty_anchors_percentage = (len(empty_anchors) / len(all_anchors)) * 100
        caracteristicas["URL_ancla"] = 1 if empty_anchors_percentage < 31 else (0 if empty_anchors_percentage <= 67 else -1)
    except:
        caracteristicas["URL_ancla"] = 0

    try:
        response = session.get(url, timeout=1)
        soup = BeautifulSoup(response.content, 'html.parser')
        meta_tags = [tag['content'] for tag in soup.find_all('meta', attrs={'http-equiv': 'refresh'})]
        caracteristicas["Tags"] = -1 if meta_tags else 1
    except:
        caracteristicas["Tags"] = 0

    try:
        response = session.get(url, timeout=1)
        forms = BeautifulSoup(response.content, 'html.parser').find_all('form')
        sfh_untrustworthy = any(form.get('action') in ["", "about:blank"] or form.get('action') and not form.get('action').startswith("https://") for form in forms)
        caracteristicas["SFH"] = -1 if sfh_untrustworthy else 1
    except:
        caracteristicas["SFH"] = 0

    try:
        response = session.get(url, timeout=1)
        caracteristicas["Submit_email"] = -1 if "mailto:" in response.text else 1
    except:
        caracteristicas["Submit_email"] = 0

    try:
        whois_info = whois.whois(url)
        caracteristicas["Abnormal_URL"] = 1 if whois_info.domain_name else -1
    except:
        caracteristicas["Abnormal_URL"] = 0

    try:
        response = session.get(url, timeout=1, allow_redirects=True)
        redirects = len(response.history)
        caracteristicas["Forwarding"] = 1 if redirects <= 1 else (0 if redirects <= 4 else -1)
    except:
        caracteristicas["Forwarding"] = 0

    try:
        response = session.get(url, timeout=1)
        caracteristicas["Pop_up"] = -1 if "window.open(" in response.text.lower() else 1
    except:
        caracteristicas["Pop_up"] = 0

    try:
        response = session.get(url, timeout=1)
        caracteristicas["IFrame"] = -1 if "<iframe>" in response.text.lower() else 1
    except:
        caracteristicas["IFrame"] = 0

    try:
        whois_info = whois.whois(url)
        fecha_actualizacion = whois_info.updated_date
        if isinstance(fecha_actualizacion, list):
            fecha_actualizacion = fecha_actualizacion[0]
        if fecha_actualizacion:
            edad_dominio = (datetime.now() - fecha_actualizacion).days
            caracteristicas["Domain_edad"] = 1 if edad_dominio >= 183 else -1
        else:
            caracteristicas["Domain_edad"] = 0
    except:
        caracteristicas["Domain_edad"] = 0

    try:
        registros_dns = dns.resolver.resolve(url, 'A')
        caracteristicas["Registro_DNS"] = 1 if registros_dns else -1
    except:
        caracteristicas["Registro_DNS"] = 0

    return caracteristicas

def procesar_datos_en_lotes(data, batch_size, tipo):
    resultados = []
    count = 0
    with requests.Session() as session:
        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            for row in batch:
                try:
                    url = row[0]
                    caracteristicas = recolectar_datos_sitioweb(url, session)
                    caracteristicas["tipoUrl"] = tipo
                    resultados.append(caracteristicas)
                    count+=1
                    print(url)
                    print(count)
                except Exception as e:
                    print(f"Error procesando la URL {url}: {e}")
    return resultados

def guardar_resultados_csv(output_file, resultados):
    try:
        if resultados:
            df_resultados = pd.DataFrame(resultados)
            df_resultados.to_csv(output_file, index=False)
            print(f"Resultados guardados en {output_file}")
        else:
            print("No hay resultados para guardar.")
    except Exception as e:
        print(f"Error al guardar resultados en CSV: {e}")

if __name__ == "__main__":
    files_and_types = [
        ("/Users/chris/Documents/VISION ARTIFICIAL/Antipishing/urlValido2.csv", "valido"),
        ("/Users/chris/Documents/VISION ARTIFICIAL/Antipishing/urlPishing2.csv", "phishing")
    ]

    batch_size = 1
    resultados_finales = []

    for file_name, tipo in files_and_types:
        tipo_valor = 1 if tipo == "valido" else 0
        datos = cargar_csv_a_lista(file_name)
        if datos:
            resultados_finales.extend(procesar_datos_en_lotes(datos, batch_size, tipo_valor))

    guardar_resultados_csv("/Users/chris/Documents/VISION ARTIFICIAL/Antipishing/resul_total2.csv", resultados_finales)
    print("Datos exportados a /Users/chris/Documents/VISION ARTIFICIAL/Antipishing/resul_total2.csv")
