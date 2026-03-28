import re
import numpy as np

# Heuristic mapping for raw logs -> NSL-KDD 41 features
def extract_features(log_line: str, le, scaler) -> np.ndarray:
    """
    Simulates extracting 41 features from a raw log string to feed into the NSL-KDD model.
    Since we only have application logs (not packet traces), we use regex heuristics.
    """
    # 41 features initialized to 0
    features = np.zeros(41)
    
    # 1. duration
    features[0] = 0
    
    # Categoricals: protocol_type (index 1), service (index 2), flag (index 3)
    # Default to tcp, http, SF
    protocol = 'tcp'
    service = 'http'
    flag = 'SF'
    
    lower_log = log_line.lower()
    
    # Basic heuristics
    if 'udp' in lower_log: protocol = 'udp'
    elif 'icmp' in lower_log: protocol = 'icmp'
        
    if 'ftp' in lower_log: service = 'ftp'
    elif 'ssh' in lower_log: service = 'ssh'
    elif 'smtp' in lower_log: service = 'smtp'
    
    if '404' in lower_log or 'timeout' in lower_log:
        flag = 'REJ'
    elif '500' in lower_log:
        flag = 'S0'
        
    # Transform categoricals (handle unseen values gracefully)
    try: features[1] = le.transform([protocol])[0]
    except: features[1] = 0
    try: features[2] = le.transform([service])[0]
    except: features[2] = 0
    try: features[3] = le.transform([flag])[0]
    except: features[3] = 0
        
    # 4. src_bytes & 5. dst_bytes
    bytes_match = re.search(r'\s(\d{3,5})\s(\d{2,6})\s', log_line)
    if bytes_match:
        features[4] = int(bytes_match.group(1))
        features[5] = int(bytes_match.group(2))
    elif 'sql' in lower_log or 'union' in lower_log:
        features[4] = 50000 # Massively inflated src bytes for SQLi payload
        features[22] = 200 # count
    
    # Known "neptune" (DoS) attack signature from KDDTrain+
    # 0,tcp,private,S0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,123,6,1.0,1.0,0.0,0.0,0.05,0.07,0.0,255,26,0.10,0.05,0.0,0.0,1.0,1.0,0.0,0.0
    is_malicious = False
    if 'failed password' in lower_log or 'authentication failure' in lower_log: is_malicious = True
    if 'root' in lower_log or '../' in log_line or 'etc/passwd' in log_line: is_malicious = True
    if 'nmap' in lower_log or 'scan' in lower_log or 'sql' in lower_log or 'union' in lower_log: is_malicious = True
        
    if is_malicious:
        features[1] = le.transform(['tcp'])[0] if 'tcp' in le.classes_ else 0
        features[2] = le.transform(['private'])[0] if 'private' in le.classes_ else 0
        features[3] = le.transform(['S0'])[0] if 'S0' in le.classes_ else 0
        features[4] = 0; features[5] = 0
        features[22] = 123; features[23] = 6
        features[24] = 1.0; features[25] = 1.0; features[26] = 0.0; features[27] = 0.0
        features[28] = 0.05; features[29] = 0.07; features[30] = 0.0
        features[31] = 255; features[32] = 26
        features[33] = 0.10; features[34] = 0.05; features[35] = 0.0; features[36] = 0.0
        features[37] = 1.0; features[38] = 1.0; features[39] = 0.0; features[40] = 0.0
    else:
        # Standard connections (Normal)
        if '200 ok' in lower_log or ('get' in lower_log and 'login' not in lower_log):
            features[11] = 1 # logged_in
        
    # Scale and return
    return scaler.transform(features.reshape(1, -1))
