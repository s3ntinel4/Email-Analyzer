import requests
import json
import base64

def vtbuscar_IOCs(api_key, iocs):
    """
    Função para buscar Indicators of Compromise (IOCs) usando a API do VirusTotal.

    Parâmetros:
    - api_key: Sua chave de API do VirusTotal.
    - query: O IOC que deseja buscar (pode ser um hash de arquivo, URL, domínio, etc.).

    Retorna:
    - Um dicionário com os resultados da busca.
    """
    print(iocs)
    url = f'https://www.virustotal.com/api/v3/files/{iocs}'
    headers = {
        'x-apikey': api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Lança uma exceção se a solicitação falhar

        data = response.json()
        informacoes = data['data']
        atributos = informacoes['attributes']
        analises = atributos['last_analysis_results']
        print("\n\n")

        for key, value in informacoes.items():
            if key != "attributes":
                print(f"{key} : {value}")

        for key, value in atributos.items():
            if key != "last_analysis_results":
                print(f"{key} : {value}\n")

        print("ANALISES MALICIOSAS: \n")
        for key, value in analises.items():
            if value["category"] == "malicious":
                print(f"{key}: {value}")
            
        print("\n\n")
        return None
    except requests.exceptions.RequestException as e:
        print(f'Erro ao fazer a solicitação: {e}')
        return None


def vtbuscar_URLs(api_key, query):
    
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")   
        url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        headers = {
            'x-apikey': api_key
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Lança uma exceção se a solicitação falhar

            data = response.json()
            informacoes = data['data']
            atributos = informacoes['attributes']
            analises = atributos['last_analysis_results']
            print("\n\n")

            for key, value in informacoes.items():
                if key != "attributes":
                    print(f"{key} : {value}")

            for key, value in atributos.items():
                if key != "last_analysis_results":
                    print(f"{key} : {value}\n")

            print("ANALISES MALICIOSAS: \n")
            for key, value in analises.items():
                if value["category"] != "clean":
                    print(f"{key}: {value}")
    
            print("\n\n")
            return None
    
        except requests.exceptions.RequestException as e:
            print(f'Erro ao fazer a solicitação: {e}')
            return None

def vtbuscar_IPs(api_key, ips):

        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ips}'
        headers = {
            'x-apikey': api_key
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Lança uma exceção se a solicitação falhar

            data = response.json()
            informacoes = data['data']
            atributos = informacoes['attributes']
            analises = atributos['last_analysis_results']
            print("\n\n")

            for key, value in informacoes.items():
                if key != "attributes":
                    print(f"{key} : {value}")

            for key, value in atributos.items():
                if key != "last_analysis_results":
                    print(f"{key} : {value}\n")

            print("ANALISES MALICIOSAS: \n")
            for key, value in analises.items():
                if value["category"] != "clean":
                    print(f"{key}: {value}")
            
            print("\n\n")
            return None

        except requests.exceptions.RequestException as e:
            print(f'Erro ao fazer a solicitação: {e}')
            return None

# Exemplo de utilização: 
