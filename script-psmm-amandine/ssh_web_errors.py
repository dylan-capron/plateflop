#!/usr/bin/env python3

import paramiko 

import mysql.connector 

import logging 

from getpass import getpass 

import re 

from datetime import datetime 

import os

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s') 
logger = logging.getLogger(__name__)

# Configuration SSH
ssh_config = { 
    'hostname': '192.168.10.113', 
    'username': 'monitor', 
    'key_filename': '/home/domenico/.ssh/domid_rsa', 
    'port': 22
}

# Configuration MySQL
db_config = { 
    'host': '192.168.10.152', 
    'user': 'dome', 
    'password': getpass("Entrez le mot de passe MySQL pour dome :"), 
    'database': 'plateflop'
}

# Chemin du fichier de log Nginx sur le serveur distant
nginx_log_file = '/var/log/nginx/monsite.error.log' 

def ssh_execute_command(client, command, sudo=False): 

    if sudo: 
        sudo_password = getpass("Entrez le mot de passe sudo : ") 
        command = f"sudo -S {command}"
    
    stdin, stdout, stderr = client.exec_command(command, get_pty=True)
    
    if sudo: 
        stdin.write(sudo_password + '\n') 
        stdin.flush()
    
    return stdout.read().decode(), stderr.read().decode() 


def ensure_table_exists(cursor): 
    cursor.execute(""" 
    CREATE TABLE IF NOT EXISTS error_log ( 
        id INT AUTO_INCREMENT PRIMARY KEY, 
        error_type VARCHAR(255) NOT NULL, 
        error_message TEXT NOT NULL, 
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    ) 
    """)
def insert_log(cursor, error_type, error_message, timestamp): 
    sql = "INSERT INTO error_log (error_type, error_message, timestamp) VALUES (%s, %s, %s)" 
    values = (error_type, error_message, timestamp) 
    cursor.execute(sql, values)
try:
    # Initialisation du client SSH
    client = paramiko.SSHClient() 
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # Chargement de la clé SSH
    key_password = getpass("Entrez la phrase de passe pour la clé SSH (laissez vide si pas de phrase de passe) : ") 
    key = paramiko.RSAKey.from_private_key_file(ssh_config['key_filename'], password=key_password or None)
    
    # Connexion au serveur SSH
    client.connect(ssh_config['hostname'], username=ssh_config['username'], pkey=key, port=ssh_config['port']) 
    logger.info("Connexion SSH établie avec succès.")
    
    # Lecture des logs Nginx
    logs, error = ssh_execute_command(client, f"cat {nginx_log_file}", sudo=True)
    
    if error: 
        logger.error(f"Erreur lors de la récupération des logs: {error}") 
    else: 
        logger.info("Logs Nginx récupérés avec succès.")
    
    # Connexion à MySQL
    conn = mysql.connector.connect(**db_config) 
    cursor = conn.cursor() 
    logger.info("Connexion à MySQL établie avec succès.")
    
    # Vérification de l'existence de la table
    ensure_table_exists(cursor)
    
    # Traitement des logs
    for line in logs.splitlines():
        match = re.match(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+#\d+): \*\d+ (.+)', line) 
        if match: 
            timestamp_str, error_type, process_id, error_message = match.groups() 
            timestamp = datetime.strptime(timestamp_str, '%Y/%m/%d %H:%M:%S') 
            full_message = f"{timestamp_str} srv-web nginx[{process_id}] {error_message}" 
            insert_log(cursor, "Nginx Error", full_message, timestamp)
    
    # Validation des changements dans la base de données
    conn.commit() 
    logger.info("Traitement des logs terminé avec succès.") 
except paramiko.SSHException as ssh_err: 
    logger.error(f"Erreur de connexion SSH: {ssh_err}") 
except mysql.connector.Error as db_err:
    logger.error(f"Erreur de base de données: {db_err}") 
except mysql.connector.Error as db_err: 
    logger.error(f"Erreur de base de données: {db_err}")
except Exception as e:
    logger.error(f"Une erreur inattendue s'est produite: {e}") 
finally:
    # Fermeture des connexions
    if 'cursor' in locals(): 
        cursor.close() 
    if 'conn' in locals() and conn.is_connected(): 
        conn.close() 
    if 'client' in locals(): 
        client.close() 
    logger.info("Toutes les connexions ont été fermées.")