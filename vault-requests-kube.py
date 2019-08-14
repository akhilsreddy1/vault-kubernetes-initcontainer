#!/usr/bin/env python3

import json
import logging
import os
import warnings
import requests
warnings.filterwarnings("ignore")

vault_role = os.environ.get('VAULT_ROLE')
vault_url = os.environ.get('VAULT_URL')
vault_skip_ssl = os.environ.get('VAULT_SKIP_VERIFY')
vault_k8s_endpoint = os.environ.get('VAULT_K8S_ENDPOINT')
secret_kv_path = os.environ.get('VAULT_SECRET_PATH')
secret_target_path = os.environ.get('SECRET_TARGET_PATH')
secret_target_file = os.environ.get('SECRET_TARGET_FILE')
secrets_type = os.environ.get('SECRET_TYPE')

logging.basicConfig(
    format='%(levelname) -5s %(asctime)s %(funcName)- -20s: %(message)s',
    datefmt='%d-%b-%y %H:%M:%S',
    level=logging.INFO)

if any(v in (None, '') for v in[vault_url, vault_role, secret_kv_path, secret_target_path, secret_target_file, secrets_type]):
    logging.error("Environment Variables not passed incorrectly")
    raise SystemExit(1)

if vault_skip_ssl in (None, False):
    certspath = False
    logging.info("Skipping SSL while connecting to Vault")
else:
    certspath = '/etc/tls/ca.crt'

if vault_k8s_endpoint in ('', None):
    vault_k8s_endpoint = 'kubernetes'

file_mode = True if secrets_type.lower() == 'file' else False
env_mode = True if secrets_type.lower() == 'variables' else False


def get_kubernetes_token():

    logging.info("Getting POD Default service account token")

    try:
        with open('/var/run/secrets/kubernetes.io/serviceaccount/token', mode='r') as f1:
            return f1.read()
    except IOError:
        logging.exception(
            'Default Service account token file not found in Pod')
        raise SystemExit(1)


def get_client_token():

    try:
        payload = {"jwt": get_kubernetes_token(), "role": vault_role}

        logging.info("Getting Vault client token using k8s-auth-method ")
        response = requests.post(
            url=vault_url + '/v1/auth/'+vault_k8s_endpoint+'/login',
            data=json.dumps(payload),
            timeout=(25, 25),
            verify=certspath)

    except requests.ConnectionError as err:
        logging.exception(
            f'Connectivity Error for Vault URL {vault_url} :: {err}')
        raise SystemExit(1)
    except Exception as err:
        logging.exception(
            f'Could not get a Client Token while authenticating with Vault :: {err}')
        raise SystemExit(1)

    if response.status_code == requests.codes.ok:
        client_token = json.loads(response.content)['auth']['client_token']
        logging.info('Client Token Fetched')
        return client_token
    else:
        logging.error(
            f'Invalid API request while authenticating with Vault. Status Code : {response.status_code} Response : {response.reason} {response.json()}')
        raise SystemExit(1)


def get_secret_vault(client_token):

    logging.info('Getting Secrets from Vault')

    try:
        response = requests.get(
            url=vault_url + '/v1/secret/' + secret_kv_path,
            headers={"X-Vault-Token": client_token},
            timeout=(25, 25),
            verify=certspath)

    except requests.ConnectionError:
        logging.exception(f'Connectivity Error for Vault URL {vault_url}')
        raise SystemExit(1)
    except Exception as err:
        logging.exception(
            f'Could not retrieve secrets from Vault. Exception :: {err}')
        raise SystemExit(1)

    if response.status_code == requests.codes.ok:

        try:
            if file_mode:
                with open((secret_target_path + os.sep + secret_target_file), 'w') as f1:
                    f1.write(json.loads(response.content)
                             ['data'][secret_target_file])
                logging.info(
                    f'Secrets File written to : {secret_target_path}/{secret_target_file}')

            if env_mode:
                secrets = json.loads(response.content)['data']
                with open((secret_target_path + os.sep + secret_target_file), 'w') as f1:
                    for k, v in secrets.items():
                        f1.write(k + '=' + "'" + v + "'" + '\n')
                logging.info(
                    f'Secret Variables written to : {secret_target_path}/{secret_target_file}')
        except IOError:
            logging.exception(
                'Secrets target path/file not found,or unable to open,Exiting')
            raise SystemExit(1)
        except Exception as err:
            logging.exception(f'Error Writing Secrets :: {err}')
            raise SystemExit(1)
    else:
        logging.error(
            f"Invalid API request while getting secrets from Vault. Status Code : {response.status_code} Response : {response.reason} {response.json()}")
        raise SystemExit(1)


if __name__ == "__main__":
    logging.info('Vault-Init Container Started')

    client_token = get_client_token()

    get_secret_vault(client_token)

    logging.info('Vault-Init Container Completed')
