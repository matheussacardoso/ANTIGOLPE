import requests
import json

links = { 
    #array que será armazenado os links
    "https://amazon.akjzyy.cn/amazc/load?v=fb1619018"
}

#para ter acesso a API e cria-se uma variável para fazer os requests
api_key = 'c328766e633794711fffdd6eb36bc0d20f6d3ee0b04a9e097ff7798dfe098e45'

#de onde vc vai puxar a funcionalidade para fazer a análise dos links
url = 'https://www.virustotal.com/vtapi/v2/url/report'

#verificar cada link até nn sobrar nenhum
for site in links:
    #conectar a apikey com os links; 
    #resource = o link que vc deseja analisar e importante para setar get request
    params = {'apikey': api_key, 'resource': site}
    #usa a biblioteca requests e a função get que irá pegar a "url" 
    #ou seja, o virustotal para fazer a análise da url e irá analisar baseado nos "params" e ter a informação
    response = requests.get(url,params=params)
     #acessar a informação do response no formato JSON, se é malicioso ou não
    response_json = json.loads (response.content) 

    if response_json['positives'] <= 0:
        with open ('index2.html','a') as vt:
            vt.write(site) and vt.write('\tNão é malicioso\n')

    elif response_json['positives'] >= 3:
        with open ('index2.html','a') as vt:
            vt.write(site) and vt.write('\t Talvez seja malicioso\n')

    elif response_json['positives'] >= 4:
        with open ('index2.html','a') as vt:
            vt.write(site) and vt.write('\tÉ malicioso\n')

    else:
        print('url not found')
