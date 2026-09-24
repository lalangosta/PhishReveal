import email
from email import policy
import re
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

class PhishReveal:
    def __init__(self):
        self.suspicious_hosts = [
            'sites.google.com',
            'firebaseapp.com',
            'notion.site',
            'canva.site',
            'weebly.com'
        ]

    def parse_eml(self, file_path):
        """Lee y extrae la información básica y el cuerpo de un archivo .eml"""
        try:
            with open(file_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            
            subject = msg.get('subject', 'Sin asunto')
            sender = msg.get('from', 'Remitente desconocido')
            
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type in ["text/plain", "text/html"]:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode(msg.get_content_charset() or 'utf-8', errors='ignore')
                    
            return {'subject': subject, 'sender': sender, 'body': body}
        except Exception as e:
            print(f"Error al leer el archivo .eml: {e}")
            return None

    def extract_urls(self, text_or_html):
        """Extrae todas las URLs del cuerpo del correo"""
        urls = set()
        # Buscamos enlaces en etiquetas HTML si es formato HTML
        soup = BeautifulSoup(text_or_html, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            urls.add(a_tag['href'])
            
        # Extraemos mediante expresiones regulares para texto plano
        regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
        matches = re.findall(regex, text_or_html)
        for match in matches:
            urls.add(match[0])
            
        return list(urls)

    def analyze_url(self, url):
        """Analiza la URL buscando indicadores de riesgo y analiza el destino web"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        is_suspicious_host = any(host in domain for host in self.suspicious_hosts)
        analysis_result = {
            'url': url,
            'domain': domain,
            'hosted_on_free_platform': is_suspicious_host,
            'has_password_form': False,
            'screenshot_path': None,
            'risk_level': 'BAJO'
        }

        # Si el enlace apunta a un servicio de alojamiento gratuito, inspeccionar la web
        if is_suspicious_host:
            print(f"[*] Inspeccionando URL sospechosa: {url}")
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
                )
                page = context.new_page()
                
                try:
                    # Timeout de 15 segundos para evitar bloqueos
                    page.goto(url, timeout=15000, wait_until="networkidle")
                    
                    # Buscar campos de contraseña en el DOM
                    password_inputs = page.locator('input[type="password"]').count()
                    
                    if password_inputs > 0:
                        analysis_result['has_password_form'] = True
                        analysis_result['risk_level'] = 'ALTO (Posible Robo de Credenciales)'
                        
                        # Guardar evidencia
                        screenshot_name = f"evidencia_{domain.replace('.', '_')}.png"
                        page.screenshot(path=screenshot_name)
                        analysis_result['screenshot_path'] = screenshot_name
                    else:
                        analysis_result['risk_level'] = 'MEDIO (Plataforma gratuita, sin formulario visible)'
                        
                except Exception as e:
                    analysis_result['error'] = str(e)
                finally:
                    browser.close()
                    
        return analysis_result

    def generate_report(self, email_data, url_analyses):
        """Genera un informe estructurado en formato JSON"""
        report = {
            'metadata': {
                'subject': email_data['subject'],
                'sender': email_data['sender']
            },
            'threat_intelligence': {
                'total_urls_found': len(url_analyses),
                'findings': url_analyses
            }
        }
        
        with open('phishreveal_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
            
        print("[+] Análisis completado. Informe generado en 'phishreveal_report.json'")


if __name__ == "__main__":
    # Ruta al correo sospechoso en formato .eml 
    sample_eml = "correo_sospechoso.eml"
    
    scanner = PhishReveal()
    print(f"[*] Parseando correo: {sample_eml}")
    
    email_data = scanner.parse_eml(sample_eml)
    
    if email_data:
        extracted_urls = scanner.extract_urls(email_data['body'])
        print(f"[*] Se encontraron {len(extracted_urls)} URLs.")
        
        results = []
        for url in extracted_urls:
            if url.startswith('http'):
                results.append(scanner.analyze_url(url))
                
        scanner.generate_report(email_data, results)