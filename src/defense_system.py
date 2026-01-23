import joblib
import pandas as pd
import time
import os
import sys
from scapy.all import sniff, IP
from collections import defaultdict
from pathlib import Path
import numpy as np

# --- CONFIGURAÇÕES ---
# Ajuste de caminho para garantir que encontre a pasta model
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "model" / "botnet_rf.pkl"
WINDOW_SIZE = 5  # Analisa o tráfego em janelas de 5 segundos

# --- CARREGAMENTO DO MODELO ---
try:
    print(f"📂 Carregando modelo de: {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)
    
    # Tenta obter os nomes das features automaticamente do modelo
    if hasattr(model, 'feature_names_in_'):
        EXPECTED_FEATURES = list(model.feature_names_in_)
        print(f"✅ Modelo carregado! Esperando {len(EXPECTED_FEATURES)} colunas.")
    else:
        # Fallback caso o modelo seja antigo (improvável com sklearn recente)
        print("⚠️ Aviso: Não foi possível ler os nomes das features do modelo.")
        sys.exit(1)

except FileNotFoundError:
    print(f"❌ Erro: Arquivo não encontrado em {MODEL_PATH}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Erro crítico ao carregar modelo: {e}")
    sys.exit(1)

# Dicionário para armazenar estatísticas temporárias dos IPs
traffic_stats = defaultdict(lambda: {
    'start_time': time.time(),
    'packet_count': 0,
    'byte_count': 0,
    'src_ip': ""
})

def block_ip(ip):
    """Executa o comando de bloqueio no Linux via Iptables."""
    print(f"🚫 [AÇÃO] Bloqueando IP: {ip} ...")
    # -I INPUT 1: Insere a regra na PRIMEIRA posição (prioridade máxima)
    os.system(f"sudo iptables -I INPUT -s {ip} -j DROP")

def process_and_predict(ip_src, stats):
    duration = (time.time() - stats['start_time']) * 1000000 # microssegundos
    if duration <= 0: duration = 1
    
    # Criar DataFrame com 68 colunas zeradas
    input_data = {feature: 0.0 for feature in EXPECTED_FEATURES}
    
    # Cálculos estatísticos básicos
    lens = np.array(stats['lengths'])
    iats = np.array(stats['iats'])
    
    # Preenchendo as Features de Fluxo (Flow)
    input_data['Flow Duration'] = duration
    input_data['Total Fwd Packets'] = stats['packet_count']
    input_data['Total Length of Fwd Packets'] = stats['byte_count']
    input_data['Flow Packets/s'] = (stats['packet_count'] / duration) * 1000000
    input_data['Flow Bytes/s'] = (stats['byte_count'] / duration) * 1000000
    
    # Features de Tamanho de Pacote
    input_data['Fwd Packet Length Max'] = np.max(lens)
    input_data['Fwd Packet Length Min'] = np.min(lens)
    input_data['Fwd Packet Length Mean'] = np.mean(lens)
    input_data['Fwd Packet Length Std'] = np.std(lens)
    
    # Features de Tempo (IAT - Inter Arrival Time)
    if len(iats) > 0:
        input_data['Flow IAT Mean'] = np.mean(iats)
        input_data['Flow IAT Max'] = np.max(iats)
        input_data['Flow IAT Min'] = np.min(iats)
        input_data['Flow IAT Std'] = np.std(iats)

    # Organiza as colunas exatamente como o modelo foi treinado
    df_input = pd.DataFrame([input_data])[EXPECTED_FEATURES]
    
    # A IA toma a decisão baseada em todos os 68 parâmetros
    prob = model.predict_proba(df_input)[0][1]
    prediction = model.predict(df_input)[0]
    
    print(f"🧠 [IA] Análise de {ip_src}: Confiança de Bot em {prob*100:.2f}%")
    
    return prediction

network_stats = {}

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        pkt_len = len(packet)
        current_time = time.time()

        if ip_src not in network_stats:
            network_stats[ip_src] = {
                'start_time': current_time,
                'last_timestamp': current_time,
                'packet_count': 0,
                'byte_count': 0,
                'lengths': [],
                'iats': [] # Inter-arrival times
            }

        stats = network_stats[ip_src]
        stats['packet_count'] += 1
        stats['byte_count'] += pkt_len
        stats['lengths'].append(pkt_len)
        
        # Calcula o intervalo entre pacotes (IAT)
        iat = (current_time - stats['last_timestamp']) * 1000000 # microssegundos
        stats['iats'].append(iat)
        stats['last_timestamp'] = current_time

        # Processa a cada janela de tempo
        if current_time - stats['start_time'] >= WINDOW_SIZE:
            is_bot = process_and_predict(ip_src, stats)
            if is_bot == 1:
                block_ip(ip_src)
            
            # Reinicia estatísticas
            network_stats[ip_src] = {
                'start_time': time.time(),
                'last_timestamp': time.time(),
                'packet_count': 0,
                'byte_count': 0,
                'lengths': [],
                'iats': []
            }
# --- EXECUÇÃO ---
if __name__ == "__main__":
    # Verifica se é root (necessário para sniff e iptables)
    if os.geteuid() != 0:
        print("❌ ERRO: Este script precisa ser rodado como ROOT (sudo).")
        print("Tente: sudo ../.venv/bin/python defense_system.py")
        sys.exit(1)

    print("🛡️ Monitor de Botnet Ativado. Pressione Ctrl+C para parar.")
    try:
        sniff(filter="ip", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Defesa encerrada pelo usuário.")
    except Exception as e:
        print(f"\n❌ Erro no Sniffer: {e}")