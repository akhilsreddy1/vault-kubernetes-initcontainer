## Vault-kubernetes-initcontainer

Vault-kubernetes-initcontainer is a small application that runs as an Init Container in Kubernetes to authenticate with Vault using Kubernetes auth method. Vault can run inside or outside kubernetes cluster.

Vault-kubernetes-initcontainer runs as an Init Container to do below stuff,

1)	Retrieve the Client token from Vault presenting a Service token of Pod and a Role it can assume.

2)	Retrieve secrets from Vault from a specified path 

3)	Place the secret grabbed into a shared volume which can be used by all other App containers running in same Pod like below. It can retreive a secret file or secret variables and Apps can use it accordingly.

## Parameters to be passed: 

- `VAULT_URL`	      : Address to the Vault server, including the protocol and port (like https://vault.default.svc.cluster.local:8200)
- `VAULT_ROLE`	      : Vault role that Application can assume for authentication.
- `VAULT_SECRET_PATH` : Path in Vault form where secrets have to be fetched
- `VAULT_SKIP_VERIFY` : To skip SSL validation while connecting to Vault. (Boolean : True/False) Certs will be taken from /etc/tls/ca.crt if set to True 
- `VAULT_K8S_ENDPOINT`: Path where Kubernetes auth method is enabled (ex : crs-kubernetes-stage-cluster) . Helps when 1 vault is connected to multiple k8s clusters. If no value is passed ,it is be set to default k8s auth path "kubernetes".
- `SECRET_TARGET_PATH`:	Path in Pod Volumes where secrets have to stored
- `SECRET_TARGET_FILE`:	Name of the file to store secret in above location
- `SECRET_TYPE`	      : {file / Variables} Indicates whether secrets in Vault is a file or individual Variables

Serive Account tokens are grabbed from default path: `/var/run/secrets/kubernetes.io/serviceaccount/token`

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
