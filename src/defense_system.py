import joblib
import pandas as pd
import time
import os
from scapy.all import sniff, IP
from collections import defaultdict
from pathlib import Path

# --- CONFIGURAÇÕES ---
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "model" / "botnet_rf.pkl"
WINDOW_SIZE = 5  # Analisa o tráfego em janelas de 5 segundos
BLOCK_THRESHOLD = 0.5 # Sensibilidade do modelo

# Carregar o modelo
try:
    model = joblib.load(MODEL_PATH)
    print("✅ Modelo carregado com sucesso.")
except:
    print("❌ Erro ao carregar o modelo. Verifique o caminho.")
    exit()

# Dicionário para armazenar estatísticas temporárias dos IPs
traffic_stats = defaultdict(lambda: {
    'start_time': time.time(),
    'packet_count': 0,
    'byte_count': 0,
    'src_ip': ""
})

def block_ip(ip):
    """Executa o comando de bloqueio no sistema operacional."""
    print(f"🚫 BLOQUEANDO IP: {ip} via iptables...")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

def process_and_predict(ip_data):
    """
    Converte os dados acumulados no formato que o Random Forest espera.
    Ajuste as chaves abaixo para bater com as colunas do seu treinamento.
    """
    duration = time.time() - ip_data['start_time']
    
    # Exemplo de mapeamento de features (deve ser igual ao seu features.py)
    df_input = pd.DataFrame([{
        'packet_count': ip_data['packet_count'],
        'byte_count': ip_data['byte_count'],
        'duration': duration,
        'rate': ip_data['packet_count'] / (duration + 0.1)
    }])
    
    # Predição
    prediction = model.predict(df_input)
    return prediction[0]

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        
        # Ignorar o próprio tráfego local se necessário
        if ip_src == "127.0.0.1": return

        # Atualizar estatísticas do IP
        stats = traffic_stats[ip_src]
        stats['packet_count'] += 1
        stats['byte_count'] += len(packet)
        stats['src_ip'] = ip_src

        # Se já coletamos dados suficientes para uma janela de tempo
        current_time = time.time()
        if current_time - stats['start_time'] >= WINDOW_SIZE:
            is_bot = process_and_predict(stats)
            
            if is_bot == 1: # Supondo 1 para BOT e 0 para BENIGN
                block_ip(ip_src)
                del traffic_stats[ip_src] # Remove da memória após bloquear
            else:
                # Reseta a janela para continuar monitorando se for legítimo
                stats['start_time'] = current_time
                stats['packet_count'] = 0
                stats['byte_count'] = 0

# --- EXECUÇÃO ---
print("🛡️ Monitor de Botnet Ativado. Escaneando tráfego...")
# sniff captura pacotes e envia para a função packet_callback
sniff(filter="ip", prn=packet_callback, store=0)