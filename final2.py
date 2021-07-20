import requests
import json

links = {
    "https://amazon.akjzyy.cn/amazc/load?v=fb1619018"
}

api_key = '?'

url = 'https://www.virustotal.com/vtapi/v2/url/report' 

for site in links:
    params = {'apikey': api_key, 'resource': site} 
    response = requests.get(url,params=params)
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
