import joblib
import pandas as pd
import time
import os
import sys
from scapy.all import sniff, IP
from collections import defaultdict
from pathlib import Path

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

def process_and_predict(ip_data):
    """
    Prepara os dados para o modelo preenchendo as colunas faltantes com zero.
    """
    current_time = time.time()
    duration = current_time - ip_data['start_time']
    
    # 1. Cria um dicionário com ZEROS para todas as colunas que o modelo espera
    # Isso evita o erro "Feature names mismatch"
    input_data = {feature: 0.0 for feature in EXPECTED_FEATURES}
    
    # 2. Preenche apenas as métricas que conseguimos calcular em tempo real
    # Mapeamos os nomes do Scapy para os nomes prováveis do Dataset (CIC-IDS)
    
    # Duração do fluxo
    if 'Flow Duration' in input_data:
        input_data['Flow Duration'] = duration
    
    # Contagem de pacotes (Assumimos como Forward Packets para simplificar)
    if 'Total Fwd Packets' in input_data:
        input_data['Total Fwd Packets'] = ip_data['packet_count']
    if 'Subflow Fwd Pkts' in input_data:
        input_data['Subflow Fwd Pkts'] = ip_data['packet_count']
        
    # Contagem de Bytes
    if 'Total Length of Fwd Packets' in input_data:
        input_data['Total Length of Fwd Packets'] = ip_data['byte_count']
    if 'Subflow Fwd Bytes' in input_data:
        input_data['Subflow Fwd Bytes'] = ip_data['byte_count']

    # Taxa (Bytes/s ou Pacotes/s)
    if 'Flow Bytes/s' in input_data and duration > 0:
        input_data['Flow Bytes/s'] = ip_data['byte_count'] / duration
    if 'Flow Packets/s' in input_data and duration > 0:
        input_data['Flow Packets/s'] = ip_data['packet_count'] / duration

    # 3. Cria o DataFrame garantindo a ORDEM EXATA das colunas
    df_input = pd.DataFrame([input_data])
    df_input = df_input[EXPECTED_FEATURES]
    
    # 4. Predição
    try:
        prediction = model.predict(df_input)
        return prediction[0]
    except Exception as e:
        print(f"⚠️ Erro na predição: {e}")
        return 0

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        
        # Ignorar localhost e tráfego local comum da VM
        if ip_src == "127.0.0.1" or ip_src == "0.0.0.0": 
            return

        # Atualizar estatísticas do IP
        stats = traffic_stats[ip_src]
        stats['packet_count'] += 1
        stats['byte_count'] += len(packet)
        stats['src_ip'] = ip_src

        # Verifica janela de tempo
        current_time = time.time()
        if current_time - stats['start_time'] >= WINDOW_SIZE:
            
            # Só faz a predição se tiver um tráfego mínimo (ex: > 10 pacotes)
            # Isso evita processar pings isolados
            if stats['packet_count'] > 10:
                is_bot = process_and_predict(stats)
                
                if is_bot == 1:
                    block_ip(ip_src)
                    del traffic_stats[ip_src] # Remove da memória
                    return

            # Reseta a janela para continuar monitorando
            stats['start_time'] = current_time
            stats['packet_count'] = 0
            stats['byte_count'] = 0

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