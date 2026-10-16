# Registry de imagens

Os manifests desta pasta instalam uma instância básica do Distribution Registry com TLS e autenticação. Antes de aplicar, crie os Secrets `registry-auth` e `registry-tls`, ajuste o armazenamento persistente e publique o serviço em um endereço acessível pelos clientes Docker e pelos nós Kubernetes.

Não inclua certificados privados, senhas ou credenciais neste repositório. Instale a CA do registry nos clientes Docker e nos nós Kubernetes que farão pull da imagem. Esta implantação simples não replica o armazenamento; use uma solução com alta disponibilidade para ambientes de produção.
