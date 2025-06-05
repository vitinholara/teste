import logging
import re
import requests
import urllib3
import time
import random
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log_format = '%(asctime)s [%(levelname)s] %(message)s'
logging.basicConfig(
    level=logging.INFO,
    format=log_format,
    handlers=[
        logging.FileHandler("violations_log3.txt", mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class IDDocHTMLValidator:
    def __init__(self, base_url, start_id=270001, end_id=318106):
        self.base_url = base_url
        self.start_id = start_id
        self.end_id = end_id
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)"
        ]
        self.proxies = []
        self.violations_level1 = []
        self.violations_level2 = []
        self.violations_level3 = []

    def get_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
            'Referer': 'https://sig.cefetmg.br/',
            'Connection': 'keep-alive'
        }

    def get_random_proxy(self):
        if self.proxies:
            proxy_url = random.choice(self.proxies)
            return {'http': proxy_url, 'https': proxy_url}
        return None

    def run(self):
        for count, iddoc in enumerate(range(self.start_id, self.end_id + 1), 1):
            url = self.base_url.format(iddoc)
            logging.info(f"[{iddoc}] Verificando HTML da URL: {url}")

            for attempt in range(5):
                try:
                    headers = self.get_headers()
                    proxies = self.get_random_proxy()
                    response = self.session.get(
                        url,
                        headers=headers,
                        proxies=proxies,
                        verify=False,
                        timeout=10
                    )

                    if response.status_code == 403:
                        raise Exception("Acesso negado (403)")

                    if self.is_blocked_content(response.text):
                        raise Exception("Conteúdo bloqueado ou captcha")

                    if response.status_code != 200:
                        break

                    soup = BeautifulSoup(response.text, 'html.parser')
                    text_content = soup.get_text(separator=' ', strip=True)

                    cpf_found, _ = self.check_cpf_patterns(text_content)

                    if cpf_found:
                        logging.warning(f"[{iddoc}] ⚠️ Expressão sensível detectada na página: {url}")
                        if url not in self.violations_level1:
                            self.violations_level1.append(url)

                        if self.has_document_keywords(text_content):
                            logging.warning(f"[{iddoc}] ⚠️ Casamento com palavras como CPF/Identidade.")
                            if url not in self.violations_level2:
                                self.violations_level2.append(url)

                            if self.check_sensitive_association(text_content):
                                logging.error(f"[{iddoc}] ❌ Associação sensível confirmada.")
                                if url not in self.violations_level3:
                                    self.violations_level3.append(url)
                                # Evitar duplicação: remove se já classificou como nível 3
                                if url in self.violations_level1:
                                    self.violations_level1.remove(url)
                                if url in self.violations_level2:
                                    self.violations_level2.remove(url)
                    else:
                        logging.info(f"[{iddoc}] ✅ Página verificada e segura.")
                    break

                except requests.exceptions.ProxyError:
                    logging.error(f"[{iddoc}] ❌ Falha no proxy.")
                    continue

                except Exception as e:
                    self.backoff_retry(attempt)
                    logging.debug(f"[{iddoc}] Tentativa {attempt + 1}/5 falhou: {e}")

            time.sleep(random.uniform(0.5, 1.5))

            if count % 199 == 0:
                logging.info("🕒 Aguardando 1,5 minutos após 199 requisições...")
                time.sleep(90)

        self.report_results()

    def backoff_retry(self, attempt):
        wait = min(60, 2 ** attempt + random.uniform(0, 1))
        logging.info(f"⏳ Esperando {wait:.2f}s antes de nova tentativa.")
        time.sleep(wait)

    def is_blocked_content(self, html):
        return any(keyword in html.lower() for keyword in ['captcha', 'acesso negado', 'erro de segurança'])

    def check_cpf_patterns(self, text):
        cpf_patterns = [
            r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b",
            r"\b\d{3}\.\d{3}\.\d{5}\b",
            r"\b\d{9}-\d{2}\b",
            r"\b\d{11}\b",
            r"\b\d{6}\.\d{3}-\d{2}\b"
        ]
        matches = []
        for pattern in cpf_patterns:
            matches.extend(re.findall(pattern, text))
        return (len(matches) > 0), matches

    def has_document_keywords(self, text):
        doc_keywords = ['cpf', 'identidade', 'documento', 'rg', 'registro', 'cadastro']
        text_lower = text.lower()
        return any(kw in text_lower for kw in doc_keywords)

    def check_sensitive_association(self, text):
        sensitive_keywords = [
            'nome', 'aluno', 'professor', 'docente', 'discente', 'coordenador', 'solicitante', 'responsavel', 'orientador',
            'fiscal', 'servidor', 'bolsista', 'voluntario', 'colaborador', 'estagiario'
        ]
        email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
        text_lower = text.lower()
        has_kw = any(kw in text_lower for kw in sensitive_keywords)
        has_email = re.search(email_pattern, text)
        return has_kw or has_email

    def report_results(self):
        print("\n🔴 [Nível 3] Violações críticas com associação a algum tipo de pessoa:")
        for link in self.violations_level3:
            print(link)

        print("\n🟠 [Nível 2] Expressões com contexto de documento:")
        for link in self.violations_level2:
            print(link)

        print("\n🟡 [Nível 1] Expressões numéricas sensíveis detectadas:")
        for link in self.violations_level1:
            print(link)

# Execução
if __name__ == "__main__":
    base_url = "https://sig.cefetmg.br/public/jsp/documentos/documento_visualizacao.jsf?idDoc={}"
    validator = IDDocHTMLValidator(base_url)
    validator.run()
