# Email-Analyzer
                                                 
My first email analyzer for extracting IOCs and also integrated search of the same IOCs on the VirusTotal platform via API key.

To use the integration via VirusTotal, it is necessary to create an account on the platform to use the VirusTotal APIv3.

The first wordlist used in the current project has words in Brazilian Portuguese only, but you can use any wordlist of your choice for a wider range of email searches.

The modules used in the tool can be installed using the command:
```
pip install requests regex optparse email hashlib urllib os
```
The tool will use .eml files as a base to read emails, the formatting and extraction is based on the markup of .eml files.

# Using the Tool

The use is based on extracting important fields from the header and also IOCs such as URLs, hashes and IPs contained in the email.

For basic use with field extraction, IPs and URLs:
```
python3 email_analyzer.py -e emailFile.eml
```

To search for incidents using a wordlist, use the "-l" parameter:
```
python3 email_analyzer.py -e emailFile.eml -l wordlist.txt
```

To search for hashes, use the "-H" parameter: 
```
python3 email_analyzer.py -e emailFile.eml -H
```

Finally, for integration with the VirusTotal API, use the "-v" parameter:
```
python3 email_analyzer.py -e emailFile.eml -v
```

NOTE: To search for hashes on the platform, the "-H" parameter will be required for the search.
