import time
from fastapi import FastAPI, HTTPException, Request, Body
from helper import serveranalyzer
from exception import SecurityAlertError, InvalidLogFormatError
from dbase import init_db, get_all_logs

app = FastAPI(
    title='Security Analyzer API',
    description='API untuk memantau server',
    version='1.0.0'
)

# Inisialisasi analyzer
analyzer = serveranalyzer()
#penyimpanan sementara untuk tracking IP dan waktu req
request_history = {}
#panggil fungsi inisialisasi database
init_db()

@app.get("/")
def home():
    return {'status': 'online', 'messages': 'Security Log Analyzer API Ready'}

@app.post("/analyze")
def analyze_log(request: Request, log_data: dict = Body(...)):
    # Membaca informasi jaringan dari client
    client_ip = request.client.host
    user_agent = request.headers.get('user-agent', '').lower()
    current_time  = time.time()

    log_data['client_ip'] = client_ip
    log_data['user_agent'] = user_agent
    
    print(f"\n[NETWORK LOG] Incoming connection from IP: {client_ip}")
    print(f"[NETWORK LOG] User-Agent: {user_agent}\n")


    if client_ip not in request_history:
        request_history[client_ip] = []

    #delete timestamp yang sudah lebih dari 60 detik ===

    request_history[client_ip] = [
        t for t in request_history[client_ip] if current_time - t < 60
    ]

    if len(request_history[client_ip]) >= 3:
        raise HTTPException(
            status_code=429,
            detail='[RATE LIMIT EXCEEDED] Terlalu banyak permintaan! Coba lagi setelah 1 menit.'
        )

    request_history[client_ip].append(current_time)

    
    if 'curl' in user_agent:
        raise HTTPException(
            status_code=403,
            detail='[SECURITY BLOCK] Request dari tools cURL/Automated Script ditolak!'
        )
    try:
        result = analyzer.analyze(log_data)
        return {'status': 'success', 'detail': result}
    except SecurityAlertError as e:
        raise HTTPException(status_code=400, detail=f'[ALERT SECURITY] {str(e)}')
    except InvalidLogFormatError as e:
        raise HTTPException(status_code=422, detail=f'[FORMAT ERROR] {str(e)}')

@app.get('/logs')
def fetch_logs():
    data = get_all_logs()
    return{'status' : 'success', 'total_logs': len(data), 'data' : data}