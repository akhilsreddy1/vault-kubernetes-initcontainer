## Vault-kubernetes-initcontainer

Vault-kubernetes-initcontainer is a small application that runs as an Init Container in Kubernetes to authenticate with Vault using Kubernetes auth method. Vault can run inside or outside kubernetes cluster.

Vault-kubernetes-initcontainer runs as an Init Container in Kubernetes to do below stuff,

Retrieve the Client token from Vault presenting a Service token of Pod and a Role it can assume.

Retrieve secrets from Vault from a specified path

Place the secret grabbed into a shared volume which can be used by all other App containers running in same Pod . It can retreive a secret file or secret variables and Apps can use it accordingly.

## Parameters to be passed: 

- `VAULT_URL`	      : Address to the Vault server, including the protocol and port (like https://vault.default.svc.cluster.local:8200)
- `VAULT_ROLE`	      : Vault role that Application can assume for authentication.
- `VAULT_SECRET_PATH` : Path in Vault form where secrets have to be fetched
- `SECRET_TARGET_PATH`:	Path in Pod Volumes where secrets have to stored
- `SECRET_TARGET_FILE`:	Name of the file to store secret in above location
- `SECRET_TYPE`	      : {file / Variables} Indicates whether secrets in Vault is a file or individual Variables
- `VAULT_SKIP_VERIFY `: (True) To skip SSL while connecting to Vault.


Serive Account tokens are grabbed from default path: `/var/run/secrets/kubernetes.io/serviceaccount/token`

Kubernetes auth endpoint inside Vault is configured to use default path :`/v1/auth/kubernetes/login`

Certs taken from /etc/tls/ca.crt ,assuming its mounted to Pod as Volume if `VAULT_SKIP_VERIFY` is not set.
 

Sample properties file in repo.

For passing above parameters to Init container in a more secure way is to create a `Secret in K8s` like below with above properties and pass the secret to Pod to inject environment variables. 

```
kubectl create secret generic vault-services-properties --from-env-file=./vault.properties 
``` 
  
Example Usage
---
```yaml

apiVersion: v1
kind: Pod
metadata:
  name: vault-secret-management
spec:
  initContainers:
    # Init Container
  - name: vault-init-container
    image: {image from repo} 
    imagePullPolicy: Always
    envFrom:
    # Environment variables needed for vault authentication injected from secret.     
    - secretRef:
        name: vault-services-properties  
    volumeMounts:
      # path to store the secrets after fetched from vault (Ex: /opt/config)
    - name: data
      mountPath: /opt/
      # certs path if passing ,else can be skipped by setting property VAULT_SKIP_VERIFY
    - name: certs
      mountPath: /etc/tls
  containers:
    # Application Container 1
  - name: App1
    image: {Application Image} 
    volumeMounts:
    # App reads secret file from the same Volume which is mounted by Init container above
    - name: data
      mountPath: /opt/
      subPath: config
    # Application Container 2
  - name: App2
    image: {Application Image} 
    command:
      - "sh"
      - "-c"
      - >
        source /opt/config;
        ./app.sh; # App startup script
    volumeMounts:
    # App sources secret file from the same Volume which is mounted by Init container above
    - name: data
      mountPath: /opt/
      subPath: config
  volumes:
  - name: data
    emptyDir: {}
  - name: certs
    secret:
      secretName: certs # certs for authenticating with Vault . 
