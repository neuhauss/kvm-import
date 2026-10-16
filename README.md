# Rancher KVM Manager

Extensão Rancher para importar hosts SUSE Linux com KVM/libvirt já instalado e administrá-los sem instalar software no host. Para publicar o projeto e instalar em outro ambiente, siga o [guia de implantação em quatro passos](GUIA-INSTALACAO-4-PASSOS.md).

## Recursos da versão 0.7.5

- Cadastro, validação, edição, atualização e remoção de hosts KVM existentes.
- Estado, última consulta, nome do host, CPU, memória e diagnóstico SSH/libvirt.
- Administração do host em duas opções: Cockpit original ou interface cloud native no padrão de navegação do Rancher/Harvester.
- Menu de administração por host para abrir Cockpit ou Cloud Native, mantendo a navegação lateral do KVM focada na lista de hosts.
- Interface localizada em português do Brasil e inglês, seguindo o idioma selecionado no Rancher.
- Tabelas e formulários usando cores de texto, fundo e borda do tema Rancher, com visual simplificado sem ícones decorativos.
- Visão geral do host com sistema operacional, kernel, disponibilidade, CPU, memória e tempo ativo.
- Áreas para VMs, armazenamento, rede, serviços systemd e logs, com ações de ciclo de vida de VMs e serviços registradas na auditoria.
- Cockpit aberto no mesmo domínio do Rancher, autenticado com as credenciais já salvas.
- Autenticação SSH por senha ou por chave privada; a frase secreta também é criptografada.
- Histórico de auditoria com usuário Rancher, ação, alvo e resultado.
- Autorização por Global Role do Rancher, configurável por `KVM_ALLOWED_GLOBAL_ROLES` (padrão: `admin`).
- Ícone KVM próprio na navegação lateral do Rancher.

A extensão não cria nem remove VMs e não instala pacotes nos hosts. O desligamento de VM usa a ação normal de libvirt, sem `destroy` forçado. A senha do usuário continua necessária para o login automático do Cockpit, mesmo quando a chave SSH autentica o túnel.

## Segurança e dados

A API valida a sessão do Rancher e aceita apenas Global Roles configuradas. Os segredos SSH (senha, chave privada e frase secreta) ficam criptografados no SQLite com `KVM_CREDENTIAL_KEY` e nunca são devolvidos pela API. O Cockpit é acessado por um túnel SSH que fixa a chave do servidor; o cookie de sessão Rancher não é encaminhado ao host.

O banco guarda inventário e auditoria no PVC `kvm-api-data`. Faça backup coordenado desse volume e de `KVM_CREDENTIAL_KEY`; sem a chave não é possível descriptografar os dados. Os eventos de auditoria não incluem senhas nem chaves privadas. A autorização permite administrar todos os hosts cadastrados; esta versão ainda não restringe ações por host ou por projeto.

Ao abrir o Cockpit pela primeira vez, a extensão ajusta `cockpit.conf`, guardando backup quando existe configuração anterior. Ao remover o cadastro, a restauração é tentada, mas uma falha de rede ou `sudo` não bloqueia a remoção; a reimportação do mesmo host pode reassumir a configuração marcada pela extensão.

## Build e release

Requisitos de desenvolvimento: Node.js 24+, Yarn e Python com PyYAML.

```sh
cd rancher-kvm
./node_modules/.bin/yarn build-pkg kvm-manager
```

Para preparar a release e regenerar os manifests de assets/API:

```sh
CHART_REPO_URL=https://<OWNER>.github.io/<REPOSITORY>/charts scripts/package-release.sh
```

A release GitHub `v0.7.5` aciona o workflow único de publicação da API no GHCR e Docker Hub. Configure os secrets `DOCKERHUB_USERNAME` e `DOCKERHUB_TOKEN` em Actions. O workflow de charts publica o catálogo na branch `gh-pages`. O [guia de quatro passos](GUIA-INSTALACAO-4-PASSOS.md) cobre publicação, instalação e os componentes que precisam estar acessíveis ao Rancher.

Os dados persistentes usam PVCs no StorageClass `default`, sem gravar diretamente no filesystem do nó. Ajuste o StorageClass para o padrão do cluster de destino, se necessário.

## Estrutura

- `pkg/kvm-manager/`: interface Rancher e ícone SVG.
- `service/`: API FastAPI, proxy autenticado do Cockpit e cliente SSH/libvirt.
- `charts/kvm-manager/`: chart que registra o `UIPlugin`.
- `deploy/`: manifests de referência, ConfigMaps e catálogo.
- `deploy/container-image/`: overlay Kustomize que troca o modo ConfigMap pelo container Docker da API.
- `scripts/`: empacotamento e geração dos ConfigMaps da release.
