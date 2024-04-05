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

"""
api_key = input("Digite sua chave API: ")

listaiocs = []
ioc_item = input("Digite o IOC que quer pesquisar: ")
listaiocs.append(ioc_item)

while True:
    
    print("Quer adicionar mais IOCs ? y/n ou digite S para sair: ")
    opcao = input("Sua resposta: ")

    if opcao == "y":
        ioc_item = input("Digite o IOC que quer pesquisar: ")
        listaiocs.append(ioc_item)
    elif opcao == "n":
        print(Posso pesquisar para você informações sobre:
                     
                    a) URLs encontradas no Email, por padrão buscarei até 4 URLs.
                    b) IPs, será buscado endereços SMTP do remetente e do servidor.
                    c) Hashes, onde será buscado, caso haja, informações sobre determinado attachment com base em seu SHA256.
                    d) Sair.
        )
        while True:    
            opcao = str(input("Digite a opcao desejada: "))
            if opcao == "a":
                for iocs in listaiocs:
                    buscar_URLs(api_key, iocs)
                break
            elif opcao == "b":
                for iocs in listaiocs:
                    buscar_IPs(api_key, iocs)
                break
            elif opcao == "c":
                for iocs in listaiocs:
                    buscar_IOCs(api_key, iocs)
                break
            else:
                print("Opcao errada !")
        break
"""    