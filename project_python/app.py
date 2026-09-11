from fastapi import FastAPI, HTTPException, Request, Body
from helper import serveranalyzer
from exception import SecurityAlertError, InvalidLogFormatError

app = FastAPI(
    title='Security Analyzer API',
    description='API untuk memantau server',
    version='1.0.0'
)

# Inisialisasi analyzer
analyzer = serveranalyzer()

@app.get("/")
def home():
    return {'status': 'online', 'messages': 'Security Log Analyzer API Ready'}

@app.post("/analyze")
def analyze_log(request: Request, log_data: dict = Body(...)):
    # Membaca informasi jaringan dari client
    client_ip = request.client.host
    user_agent = request.headers.get('user-agent', '').lower()

    log_data['client_ip'] = client_ip
    log_data['user_agent'] = user_agent
    
    print(f"\n[NETWORK LOG] Incoming connection from IP: {client_ip}")
    print(f"[NETWORK LOG] User-Agent: {user_agent}\n")

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