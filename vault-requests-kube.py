#!/usr/bin/env python3

import os
import requests
import json
import logging
import sys

vault_role = os.environ.get('VAULT_ROLE')
vault_url = os.environ.get('VAULT_URL')
vault_skip_ssl = os.environ.get('VAULT_SKIP_VERIFY')
secret_kv_path = os.environ.get('VAULT_SECRET_PATH')
secret_target_path = os.environ.get('SECRET_TARGET_PATH')
secret_target_file = os.environ.get('SECRET_TARGET_FILE')
secrets_type = os.environ.get('SECRET_TYPE')

logging.basicConfig(
    format='%(levelname) -5s %(asctime)s %(funcName)- -20s: %(message)s',
    datefmt='%d-%b-%y %H:%M:%S',
    level=logging.INFO)

if (vault_role == '' or vault_url ==
        '' or secret_kv_path == '' or secrets_type == ''):
    raise Exception(f"ERROR : Parameters passed incorrectly")

env_mode, file_mode = False, False

if secrets_type.lower() == 'file':
    file_mode = True
if secrets_type.lower() == 'variables':
    env_mode = True

if vault_skip_ssl not in ('',None):
    certspath = False
    logging.info("Skipping SSL while connecting to Vault")
else:
    certspath = '/etc/tls/ca.crt'


def get_kubernetes_token():

    logging.info("Getting POD service account token")
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', mode='r') as f1:
        return f1.read()


def get_client_token():

    try:
        logging.info("Getting Vault client token")
        payload = {"jwt": get_kubernetes_token(), "role": vault_role}

        response = requests.post(
            url=vault_url + '/v1/auth/kubernetes/login',
            data=json.dumps(payload),
            timeout=(25, 25),
            verify=certspath)

    except requests.ConnectionError:
        logging.error(f'Connectivity Error for Vault URL {vault_url}')
    except Exception as err:
        raise Exception(
            f"ERROR : Could not get a Client Token while authenticating with Vault , {err} ")

    if response.status_code == requests.codes.ok:
        client_token = json.loads((response.content))['auth']['client_token']
        logging.info('Client Token Fetched')
        return client_token
    else:
        raise Exception(
            f"ERROR : Invalid request while authenticating with Vault. Status Code : {response.status_code} Response : {response.reason} ")


def get_secret_vault(client_token):

    logging.info('Getting Secrets from Vault')

    try:
        response = requests.get(
            url=vault_url + '/v1/secret/' + secret_kv_path,
            headers={"X-Vault-Token": client_token},
            timeout=(25, 25),
            verify=certspath)

    except requests.ConnectionError:
        logging.error(f'Connectivity Error for Vault URL {vault_url}')
    except Exception as err:
        raise Exception(
            f"ERROR : While retreiving secrets from Vault. Exception : {err} ")

    if response.status_code == requests.codes.ok:

        if file_mode:
            with open((secret_target_path + os.sep + secret_target_file), mode='w') as f1:
                f1.write(json.loads(response.content)
                         ['data'][secret_target_file])
            logging.info(
                f'Secret File written to : {secret_target_path}/{secret_target_file}')

        if env_mode:
            secrets = json.loads(response.content)['data']
            with open((secret_target_path + os.sep + secret_target_file), 'w') as f1:
                for k, v in secrets.items():
                    f1.write(k + '=' + "'" + v + "'" + '\n')
            logging.info(
                f'Secret Variables written to : {secret_target_path}{secret_target_file}')

    else:
        raise Exception(
            f"ERROR : Invalid request while Fetching secrets from Vault. Status Code : {response.status_code} Response : {response.reason} ")


if __name__ == "__main__":

    logging.info('Vault-Init Container Start')

    client_token = get_client_token()

    get_secret_vault(client_token)
