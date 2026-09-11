import logging
from database import logs
from exception import SecurityAlertError, InvalidLogFormatError

# Konfigurasi logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)

class serveranalyzer:
    def __init__(self, max_allow_attempts=5):
        self.max_attempts = max_allow_attempts

    def analyze(self, log):
        server_id = log.get('server_id', 'UNKNOWN')

        # 1. Validasi keberadaan field
        if 'failed_attempts' not in log:
            logging.error(f'Server {server_id}, Key Value tidak ditemukan')
            raise InvalidLogFormatError(f'Field "failed_attempts" tidak ada di {server_id}')

        # 2. Validasi tipe data angka
        attempts = 0
        try:
            attempts = int(log['failed_attempts'])
        except ValueError:
            logging.error(f'server {server_id}, format failed_attempts "{log["failed_attempts"]}" tidak valid')
            raise InvalidLogFormatError(f'format angka tidak valid di {server_id}')

        # 3. Analisis batas keamanan (Security Alert)
        if attempts > self.max_attempts:
            logging.warning(f'Security Alert! : {server_id} mencatat sudah melakukan percobaan {attempts} kali')
            raise SecurityAlertError(f'Security Alert, {server_id} sudah melakukan {attempts} kali percobaan')

        # 4. Jika kondisi aman
        logging.info(f'server : {server_id} aman. Sudah melakukan {attempts} kali')
        return f'server {server_id} aman'