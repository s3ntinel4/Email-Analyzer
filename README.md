# Email-Analyzer
Meu primeiro analizador de email para extração de IOCs e também pesquisa integrada dos mesmos IOCs na plataforma VirusTotal via chave API.

Para utilizar a integração via VirusTotal é necessário a criação de uma conta na plataforma para uso da APIv3 do VirusTotal.
A primeira wordlist usada no projeto atual conta com palavras em português-BR somente mas pode ser usado qualquer wordlist de sua preferência para um range maior de pesquisa no email.
Os módulos usados na ferramenta podem ser instalados por meio do comando:
```
pip install requests regex optparse email hashlib urllib os
```
A ferramenta irá usar por base arquivos .eml para a leitura dos emails, a formatação e extração retirada baseia-se na marcação de arquivos .eml .
