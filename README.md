# Email-Analyzer
                                                 
Meu primeiro analizador de email para extração de IOCs e também pesquisa integrada dos mesmos IOCs na plataforma VirusTotal via chave API.

Para utilizar a integração via VirusTotal é necessário a criação de uma conta na plataforma para uso da APIv3 do VirusTotal.
A primeira wordlist usada no projeto atual conta com palavras em português-BR somente mas pode ser usado qualquer wordlist de sua preferência para um range maior de pesquisa no email.
Os módulos usados na ferramenta podem ser instalados por meio do comando:
```
pip install requests regex optparse email hashlib urllib os
```
A ferramenta irá usar por base arquivos .eml para a leitura dos emails, a formatação e extração retirada baseia-se na marcação de arquivos .eml .

# Uso da Ferramenta

O uso baseia na extração de campos importantes do cabeçalho e também IOCs como URLs, hashes e IPs contidos no email.
Para uso básico com a extração de campo, IPs e URLs:
```
python3 email_analyzer.py -e emailFile.eml
```

Para a pesquisa por incidências usando uma wordlist, usa-se o parâmetro "-l":
```
python3 email_analyzer.py -e emailFile.eml -l wordlist.txt
```

Para a pesquisa por hashes, usa-se o parâmetro "-H"
```
python3 email_analyzer.py -e emailFile.eml -H
```

Por fim para a integração com a API VirusTotal, usa-se o parâmetro "-v":
```
python3 email_analyzer.py -e emailFile.eml -v
```

OBS: Para a pesquisa por hashes na plataforma, será necessário o parâmetro "-H" para pesquisa
