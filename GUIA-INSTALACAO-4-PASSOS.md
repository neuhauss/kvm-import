# Publicar e instalar o Rancher KVM Manager

Este manual prepara o código para GitHub, publica a API no Docker Hub e instala os componentes num cluster Rancher. O Docker Hub guarda somente a imagem da API: o chart Helm e os arquivos JavaScript/CSS da extensão também precisam estar acessíveis ao Rancher. Os manifests incluem esses arquivos num ConfigMap e servem-nos dentro do cluster.

## 1. Enviar o projeto ao GitHub

Crie um repositório vazio no GitHub. Na pasta do projeto:

```sh
cd /path/to/rancher-kvm
git init -b main
git add .
git commit -m "Publish Rancher KVM Manager"
git remote add origin https://github.com/<OWNER>/<REPOSITORY>.git
git push -u origin main
```

Se a pasta já estiver clonada de um repositório, use `git remote -v` e `git status` antes de configurar outro `origin`.

No GitHub, abra **Settings → Secrets and variables → Actions** e cadastre:

- `DOCKERHUB_USERNAME`: usuário ou organização do Docker Hub.
- `DOCKERHUB_TOKEN`: access token do Docker Hub com permissão de escrita no repositório `rancher-kvm-api`.

Não coloque senha, tokens, chaves SSH, certificados privados ou `KVM_CREDENTIAL_KEY` no Git. O `.gitignore` já exclui dados locais conhecidos; revise `git status` antes de cada commit.

## 2. Criar uma release e publicar a imagem no Docker Hub

Crie uma release GitHub com a tag `v0.5.7`. O workflow `Publish KVM API image` compila `service/Dockerfile` e publica no GHCR e Docker Hub. Para o Docker Hub, configure `DOCKERHUB_USERNAME` e `DOCKERHUB_TOKEN` como secrets de Actions:

```text
docker.io/<DOCKERHUB_USERNAME>/rancher-kvm-api:0.5.7
docker.io/<DOCKERHUB_USERNAME>/rancher-kvm-api:latest
```

Também existe publicação no GHCR. Para testar localmente, antes de criar a release:

```sh
docker build -t <DOCKERHUB_USERNAME>/rancher-kvm-api:0.5.7 ./service
```

No overlay `deploy/container-image/kustomization.yaml`, altere `newName` para `docker.io/<DOCKERHUB_USERNAME>/rancher-kvm-api`. O `newTag` deve ser a versão sem o prefixo `v`:

```yaml
images:
  - name: python:3.12-slim
    newName: docker.io/seu-usuario/rancher-kvm-api
    newTag: 0.5.7
```

Se o repositório Docker Hub for privado, crie um `imagePullSecret` no namespace `rancher-kvm-registry` e adicione `imagePullSecrets` ao Pod. Para uma imagem pública, o cluster pode baixá-la sem credenciais.

## 3. Preparar e instalar no cluster Rancher

Antes de aplicar em outro ambiente, defina a URL pública do Rancher em `deploy/container-image/kvm-api.yaml` (`RANCHER_PUBLIC_ORIGIN` e `Ingress.rules.host`). O valor inicial está configurado para `rancher.example.com`. Confira também a CA do serviço Rancher em `kvm-rancher-ca`, a política de acesso `KVM_ALLOWED_GLOBAL_ROLES` e o StorageClass. O PVC de exemplo usa `default` e 1 GiB; o PVC opcional do registry usa 20 GiB. Ambos usam volumes Kubernetes, sem `hostPath` no nó.

Crie o namespace e os recursos secretos fora do Git. Uma forma de gerar e guardar uma chave de criptografia:

```sh
openssl rand -base64 48
```

Guarde esse valor num gerenciador de segredos e crie `credential-key` no Secret `kvm-api-secrets`. A mesma chave e o PVC `kvm-api-data` precisam ser preservados juntos em backup; perder a chave torna as credenciais armazenadas irrecuperáveis. Crie também `kvm-known-hosts` com as chaves SSH dos hosts verificadas por um canal confiável e `kvm-rancher-ca` com o certificado CA correto. Não aceite chaves SSH desconhecidas sem verificar sua impressão digital.

Gere novamente os assets da versão atual e aplique a API, os assets e o plugin:

```sh
CHART_REPO_URL=https://<OWNER>.github.io/<REPOSITORY>/charts scripts/package-release.sh
kubectl create namespace rancher-kvm-registry
kubectl -n rancher-kvm-registry create secret generic kvm-api-secrets \
  --from-literal=credential-key='<CHAVE_GERADA_E_GUARDADA_FORA_DO_GIT>'
kubectl -n rancher-kvm-registry create configmap kvm-known-hosts --from-file=known_hosts=<ARQUIVO_CONFERIDO>
kubectl -n rancher-kvm-registry create configmap kvm-rancher-ca --from-file=ca.crt=<CA_DO_RANCHER>
kubectl apply -k deploy/container-image
kubectl apply --server-side -f deploy/kvm-extension-assets-configmap.yaml
kubectl apply -f deploy/ui-extension.yaml
```

Use `kubectl create` para os recursos secretos/configuração; não os grave no repositório. O ConfigMap de assets é grande e deve ser gerado pelo script após compilar o pacote. O manifesto `deploy/ui-extension.yaml` inclui o Deployment, Service e registro `UIPlugin`. Se instalar pelo chart `charts/kvm-manager`, implante também os assets e a API necessários; não registre o `UIPlugin` duas vezes.

O catálogo/chart Helm é útil para distribuição por catálogo no Rancher. Publique `deploy/extension-catalog/` em GitHub Pages ou num servidor HTTPS e cadastre a URL do `index.yaml` como repositório Helm no Rancher. Para a instalação direta por manifests, não é necessário publicar um catálogo: os assets são servidos pelo Service `kvm-extension-assets` no próprio cluster.

## 4. Validar e importar hosts

Confira se `kvm-api` e `kvm-extension-assets` estão prontos e se o recurso `UIPlugin` está habilitado. Abra **KVM** na navegação lateral, escolha **Adicionar host** e informe endereço, usuário e senha. A chave SSH do host deve estar previamente verificada ou ser aceita explicitamente pelo operador. Depois, use o menu do host para abrir Cockpit ou Interface cloud native.

## O que precisa ser publicado para instalar em outro ambiente?

| Componente | Onde publicar/guardar | Necessário? |
|---|---|---|
| Código e workflows | GitHub | Sim |
| Imagem da API | Docker Hub ou GHCR | Sim, se usar o overlay `container-image` |
| Chart e `index.yaml` | GitHub Pages, OCI Helm ou servidor HTTPS | Apenas para catálogo Helm |
| Bundle da extensão | Servido pelo ConfigMap/Service no cluster ou por URL HTTPS pública | Sim; o manifesto direto já faz isso internamente |
| Secrets, CA e known_hosts | Secret manager ou criação direta no cluster | Sim; nunca enviar ao GitHub |
| Dados SQLite e chave de criptografia | PVC/backup seguro | Sim para manter hosts e credenciais |

O Docker Hub não publica o chart, o `UIPlugin`, os assets da extensão nem os Secrets. Um ambiente externo precisa de acesso HTTPS ao chart se usar catálogo, acesso do cluster à imagem do Docker Hub e persistência compatível com o StorageClass disponível. Para imagem privada, também precisa do `imagePullSecret`.

## Cuidados de atualização e backup

- Faça backup consistente do PVC `kvm-api-data` junto com o Secret `kvm-api-secrets` antes de atualizar ou recriar a API.
- Não remova o PVC durante reinstalação. `kubectl delete -f` ou apagar namespace pode remover dados dependendo da política do StorageClass.
- Em ambientes sem Harvester, altere `storageClassName: default` para uma StorageClass existente.
- O registry local em `deploy/registry/` é opcional. Para publicação de imagens ao Docker Hub, não é necessário implantá-lo.
