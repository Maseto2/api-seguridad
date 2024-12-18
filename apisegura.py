from flask import Flask, jsonify, request
from flask_cors import CORS
from vulners import Vulners
from vulners import VulnersApi
import os
import socket
import nmap
import subprocess

app = Flask(__name__)
CORS(app)  # This enables CORS for all routes

# Initialize the Nmap scanner
nm = nmap.PortScanner()

@app.route('/')
def health_check():
    return jsonify({"status": "True"})

@app.route('/simplescan', methods=['POST'])
def simple_scan():
    data = request.json
    network = data.get('network')
    
    if not network:
        return jsonify({"error": "Network IP is required"}), 400

    try:
        nm.scan(hosts=network, arguments='-T4, -F')
        
        results = []
        for host in nm.all_hosts():
            host_data = {
                "host": host,
                "ports": []
            }
            
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    host_data["ports"].append({
                        "port": port,
                        "state": nm[host]['tcp'][port]['state']
                    })
            
            results.append(host_data)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Configuración de la API Key de Vulners
#De momento no hace falta porque es con NMAP
#VULNERS_API_KEY = os.environ.get('VULNERS_API_KEY')

@app.route('/vulnscan', methods=['POST'])
def vulnscan():
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({"error": "IP address is required"}), 400
    
    # Lista de puertos a escanear
    ports_to_check = [21, 22, 25, 111, 139, 445, 512, 513, 514, 1099, 1524, 2049, 2121, 3632, 5432, 5900, 6000, 6667, 6697, 8009, 8181, 8180, 8787, 53, 80, 443, 389, 3306, 5000, 8081, 10000]  # Añade más puertos si es necesario

    # Inicializar resultados
    formatted_results = {
        ip: {
            "host": ip,
            "ports": [],
            "status": "scanned"
        }
    }
    
    # Crear una instancia de Nmap
    nm = nmap.PortScanner()

    try:
        # Ejecutar escaneo de vulnerabilidades con Nmap
        scan_args = '--script vuln -p ' + ','.join(map(str, ports_to_check))
        scan_results = nm.scan(hosts=ip, arguments=scan_args)

        # Procesar resultados
        for host in scan_results['scan']:
            for port, port_data in scan_results['scan'][host].get('tcp', {}).items():
                vulnerabilities = []
                if 'script' in port_data:
                    # Extraer vulnerabilidades reportadas por los scripts
                    for script_name, output in port_data['script'].items():
                        vulnerabilities.append(output.strip())
                else:
                    vulnerabilities.append("No known vulnerabilities found")
                
                # Agregar el puerto y sus vulnerabilidades al resultado
                formatted_results[ip]["ports"].append({
                    "port": port,
                    "vulnerabilities": vulnerabilities
                })

        # Si no se encontraron puertos accesibles
        if not formatted_results[ip]["ports"]:
            formatted_results[ip]["status"] = "no reachable ports"
        return jsonify(formatted_results)

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context=('/opt/certs/cert.pem', '/opt/certs/key.pem'))
