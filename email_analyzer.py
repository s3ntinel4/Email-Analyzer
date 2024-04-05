## Meu primeiro projeto de analizador de emails

# Lista de imports

import requests
import regex as re
import optparse
import email
from email.header import Header
import hashlib
from vt_integration import vtbuscar_IOCs, vtbuscar_IPs, vtbuscar_URLs
import os
from urllib.parse import urlparse

### Variaveis

lista_ips = []
unique_urls = []
lista_iocs = []
palavras = []
listaurls = []
attachment_hashes = []
lista_attachs = []

### Funções próprias

def get_Args():
    parser = optparse.OptionParser()
    parser.add_option("-e", "--email", dest="emailmessage", help="Arquivo de email à ser analizado.", metavar="FILE")
    parser.add_option("-H", "--hashfile", action="store_true", dest="file_hash", help="Extrai, caso exista, o SHA256 do attachment presente no email.")
    parser.add_option("-v", "--virustotal", action="store_true", dest="virustotal", help="Chama o menu de integração com VirusTotal.")
    parser.add_option("-l", "--list", dest="listakeywords", help="Arquivo .txt de keywords à serem analizadas.", metavar="FILE")
    (option, args) = parser.parse_args()

    if not option.emailmessage:
        parser.error("[+] Please enter a .eml file to be analyzed or just type -h for help. [+]")
    print("""
#     #                                                                                                                                                                                                                                       ### 
#  #  # ###### #       ####   ####  #    # ######    #####  ####     #    # #   #    ###### # #####   ####  #####    ###### #    #   ##   # #           ##   #    #   ##   #      #   # ###### ###### #####     #####  ####   ####  #         ### 
#  #  # #      #      #    # #    # ##  ## #           #   #    #    ##  ##  # #     #      # #    # #        #      #      ##  ##  #  #  # #          #  #  ##   #  #  #  #       # #      #  #      #    #      #   #    # #    # #         ### 
#  #  # #####  #      #      #    # # ## # #####       #   #    #    # ## #   #      #####  # #    #  ####    #      #####  # ## # #    # # #         #    # # #  # #    # #        #      #   #####  #    #      #   #    # #    # #          #  
#  #  # #      #      #      #    # #    # #           #   #    #    #    #   #      #      # #####       #   #      #      #    # ###### # #         ###### #  # # ###### #        #     #    #      #####       #   #    # #    # #             
#  #  # #      #      #    # #    # #    # #           #   #    #    #    #   #      #      # #   #  #    #   #      #      #    # #    # # #         #    # #   ## #    # #        #    #     #      #   #       #   #    # #    # #         ### 
 ## ##  ###### ######  ####   ####  #    # ######      #    ####     #    #   #      #      # #    #  ####    #      ###### #    # #    # # ######    #    # #    # #    # ######   #   ###### ###### #    #      #    ####   ####  ######    ###                 
    """)
    return option


def extract_attachment_hashes(eml_file):
    """
    Função para retornar os hashes dos arquivos.

    Parâmetro:
    - email: Arquivo de email passado para análise

    Retorna:
    - Uma lista contendo o nome dos arquivos e os seus respectivos hashes SHA256 encontrados no email.
    """
    
    with open(eml_file, 'rb') as arquivo:
        msg = email.message_from_binary_file(arquivo)
        
        for partes in msg.walk():
            if partes.get_content_maintype() == 'multipart':
                continue

            # Extraindo o attachment e o nome do arquivo
            nome_arquivo = partes.get_filename()
            if nome_arquivo :
                conteudo_attachment = partes.get_payload(decode=True)
                if conteudo_attachment:
                    valor_hash = hashlib.sha256(conteudo_attachment).hexdigest() # Calculando o hash do arquivo, possivel somente com a inclusão da biblioteca OS
                    attachment_hashes.append((nome_arquivo, valor_hash))
                    lista_attachs.append(valor_hash)
            
    return attachment_hashes


def buscar_URLS(emailmensagem):
    """
    Função para buscar URLs no email.

    Parâmetro:
    - email: Arquivo de email passado para análise

    Retorna:
    - Uma lista de URLs encontradas no email.
    """
    x = re.compile(r"href.+?[\'|\"]+?([^\'|\"]+)?[\'|\"]") #Regex para buscar URLs no email, como já há a separação na função main, essa função irá realizar a busca somente no corpo do email.
    urls = x.findall(emailmensagem)
    for url in urls:
        listaurls.append(url)
    urls_normalizadas = []
    for url in listaurls:
        parsed_url = urlparse(url)
        url_normalizada = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
        urls_normalizadas.append(url_normalizada.lower())  #A normalização foi necessário devido incidência de duplicatas em diversas URLs

    unique_urls = list(set(urls_normalizadas))

    for urlsencontrada in unique_urls:
        print(f"URL encontrada: {str(urlsencontrada)} \n")
    return 0


def buscar_IPs(cabecalho):
    """
    Função para buscar IPs no email.

    Parâmetros:
    - email: Arquivo de email passado para análise

    Retorna:
    - Uma lista de IPs encontrados no email
    """

    ips = re.findall(r'\s[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+', cabecalho) #Regex para buscar endereços IPv4 no email, devido ocorrências de falsos positivos, a string será tratada novamente posteriormente.
    ips6 = re.findall(r'[a-f0-9]{1,4}\:[a-f0-9]{1,4}\:[a-f0-9]{1,4}\:.+\:[a-f0-9]{1,4}', cabecalho) #Regex para buscar endereços IPv6 no email.
    listaipsv4 = list(set(ips))
    listaipsv6 = list(set(ips6))
    for ip in listaipsv4:
        print(f"IPv4 encontrado: {ip.strip()}\n")
        lista_ips.append(ip.strip())
    
    for ip in listaipsv6:
        print(f"IPv6 encontrado: {ip}\n")
        lista_ips.append(ip)


def buscar_Palavras(email, lista):
    """
    Função para buscar URLs no email.

    Parâmetros:
    - email: Arquivo de email passado para análise

    Retorna:
    - Uma lista de palavras que podem indicar tentativas de phishing ou SPAM, como "Reward", "Paypal", "prize", entre outras.
    """

    lista_de_incidentes = []
    num_incidentes = 0

    listadepalavras = open(lista, "r")
    for linha in listadepalavras:
        palavras = []
        palavra = linha.rstrip("\n") #Retirada do caractere novalinha("/n") para buscar simplificada.
        palavras.append(palavra)
        for palavra in palavras:
            if palavra in email:
                lista_de_incidentes.append(palavra)
                num_incidentes = num_incidentes + 1
    listadepalavras.close()

    for incidentes in lista_de_incidentes:
        print(f"\nIncidencia encontrada: {incidentes}")
    print(f"Ao todo foram encontradas {str(num_incidentes)} incidencias de palavras indicadoras de SPAM ou Phishing. \n\n")


def main():

    options = get_Args()
    with open(options.emailmessage, 'r', encoding="utf8") as emailmsg:
        msg = email.message_from_file(emailmsg)
        titulo = msg.get('Subject')
        retorno = msg.get('Return-Path')
        for partes in msg.walk():
            conteudo = partes.get_payload()
            header = partes.values()
            if conteudo:
                conteudoemail = "".join(str(elemento) for elemento in conteudo)
                cabecalhoemail = "".join(str(elemento) for elemento in header)
                buscar_IPs(cabecalhoemail) #Chamada da função para buscar IPs
                buscar_URLS(conteudoemail) #Chamada da função para buscar as URLs
                if options.listakeywords:
                    buscar_Palavras(conteudoemail, options.listakeywords)
                    
                break
        if titulo: print(f"Assunto: {titulo}")
        if retorno: print(f"Return-Path: {retorno}")

        if options.file_hash: #Checando a opção do hash
            eml_file = options.emailmessage 
            attachment_hashes = extract_attachment_hashes(eml_file) #Chamada da função para buscar hashes
            if attachment_hashes:
                print("Attachment Hashes:")
                for filename, valor_hash in attachment_hashes:
                    print(f"{filename}: {valor_hash}")
            else: print("Não foram encontrados attachments ! \n")
        
        if options.virustotal:
            k_api = str(input("Para usar a integração com o VirusTotal insira primeiro a chave api que irá usar: "))
            print("""Posso pesquisar para você informações sobre:
                     
                    a) URLs encontradas no Email, por padrão buscarei até 4 URLs.
                    b) IPs, será buscado endereços SMTP do remetente e do servidor.
                    c) Hashes, onde será buscado, caso haja, informações sobre determinado attachment com base em seu SHA256.
                    d) Sair
                  
                  OBS: Para usar a opção de buscar o hash, será necessário usar o -H para extração dos hashes dos arquivos.
                """)
            
            while True:
                opcao = str(input("Insira a letra da opção escolhida: "))
                if opcao == "a":
                    print("Ótima escolha, aqui está o resumo de informações das URLs encontradas: \n\n")
                    for item in unique_urls:
                        print(unique_urls)
                        #vtbuscar_URLs(k_api, item)
                    break
                elif opcao == "b":
                    print("Ótima escolha, aqui está o resumo de informações dos IPs encontrados: \n\n")
                    for item in lista_ips:
                        vtbuscar_IPs(k_api, item)
                    break
                elif opcao == "c":
                    for item in lista_attachs:
                        print("Ótima escolha, aqui está o resumo de informações dos hashes encontrados: \n\n")
                        vtbuscar_IOCs(k_api, item)
                    break
                elif opcao == "d":
                    print(f"Você optou por sair, até mais !")
                    break
                else:
                    opcao = str(print("Opção invalida! Digite uma letra novamente: "))                  

if __name__ == "__main__":
    main()