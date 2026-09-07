# Guia de operação do Esquema

[README](../README.md#português-brasileiro) · [English](guide.md)

Execute os comandos do checkout na raiz do repositório. O Esquema é um runtime
Linux; a biblioteca C e os módulos Scheme não implementam download de imagens
OCI nem uma interface de linha de comando compatível com Docker.

## Instalação

As dependências de compilação são Guile 3.0, GNU Make, compilador C compatível
com GNU, `pkg-config`, arquivos de desenvolvimento do libseccomp e cabeçalhos
Linux com Landlock. Os testes também usam cppcheck e Bash estaticamente
vinculado. O manifesto Guix fornece as ferramentas de compilação e análise;
compile o Bash separadamente:

```sh
guix shell -m manifest.scm -- make smoke
export ESQUEMA_TEST_SHELL="$(guix build bash-static:out)/bin/bash"
```

O manifesto contém nomes de pacotes, não revisões fixas dos canais Guix.
Reproduzir as dependências também exige selecionar os mesmos canais. Em outra
distribuição Linux, instale os pacotes de desenvolvimento equivalentes e execute
`make smoke`.

Instale em um prefixo do seu usuário, sem root:

```sh
make install PREFIX="$HOME/.local"
export GUILE_LOAD_PATH="$HOME/.local/share/guile/site/3.0${GUILE_LOAD_PATH:+:$GUILE_LOAD_PATH}"
guile -c '(use-modules (esquema runtime)) (display (esquema-runtime-version)) (newline)'
```

Se estiver compilando pelo Guix, execute a instalação no mesmo ambiente
`guix shell -m manifest.scm --`. A instalação padrão coloca a biblioteca em
`PREFIX/lib`, o cabeçalho C em `PREFIX/include` e os módulos Scheme em
`PREFIX/share/guile/site/3.0`. A instalação registra o diretório final da
biblioteca para a FFI; `ESQUEMA_LIBDIR` permite substituí-lo para usar um checkout
ou outra biblioteca.

Para preparar um pacote sem gravar no prefixo do sistema:

```sh
make install PREFIX=/usr DESTDIR="$PWD/package-root"
```

`LIBDIR`, `INCLUDEDIR`, `GUILE_SITE_DIR` e `DOCDIR` substituem os respectivos
diretórios finais; `DESTDIR` é acrescentado somente durante a preparação do
pacote. É possível fornecer opções de compilação e vinculação por `CPPFLAGS`,
`CFLAGS` e `LDFLAGS`.

Remova uma instalação usando as mesmas configurações de diretórios:

```sh
make uninstall PREFIX="$HOME/.local"
```

Remova pacotes da distribuição pelo gerenciador que os instalou.

## Sistemas de arquivos e API

Um rootfs é um diretório existente com o executável, seu carregador dinâmico e
suas bibliotecas, quando necessários, além de pontos de montagem como `/proc` e
`/dev`. O Esquema não baixa imagens nem resolve dependências do programa.

A demonstração autossuficiente copia um Bash estático para `/bin/sh`:

```sh
export ESQUEMA_TEST_SHELL="$(guix build bash-static:out)/bin/bash"
sh examples/build-rootfs.sh examples/rootfs-min
ESQUEMA_LIBDIR="$PWD" guile -L scheme examples/hello.scm
```

Sem Guix, defina `ESQUEMA_TEST_SHELL` com o caminho de um Bash estático existente.
A demonstração usa recursos do Bash; um shell POSIX qualquer não é equivalente.

```scheme
(use-modules (esquema runtime) (esquema container))

(define tarefa
  (make-container "tarefa" "/caminho/absoluto/para/rootfs"
                  '("/bin/sh" "-c" "echo pronto")
                  #:env '(("PATH" . "/bin") ("LANG" . "C"))
                  #:rootfs-ro? #t
                  #:supervise? #t))

(exit (run-container tarefa))
```

`run-container` aguarda e retorna o status de saída, incluindo `128 + sinal`
quando o processo termina por sinal. `exit` propaga esse status ao chamador ou
gerenciador de serviços. Erros de configuração e criação do processo também
podem gerar uma exceção Guile. `esquema-runtime-version` consulta a versão da
biblioteca carregada.

| Opção | Significado e padrão |
| --- | --- |
| `#:namespaces` | `(user mount pid uts ipc net cgroup)` por padrão. |
| `#:hostname` | Nome do contêiner por padrão. |
| `#:env` | Lista de associação com o ambiente explícito; uma lista vazia usa `PATH` e `HOME` mínimos, sem herdar o ambiente do host. |
| `#:mounts` | Entradas `(origem destino somente-leitura?)`; destino relativo ao rootfs. Padrão: nenhuma montagem bind. |
| `#:rootfs-ro?` | Solicita raiz somente para leitura; padrão `#f`. |
| `#:seccomp?`, `#:drop-caps?`, `#:landlock?` | Padrão `#t`; falha do Landlock é fatal somente no modo estrito. |
| `#:preserve-fds` | Descritores explicitamente delegados, de número 3 ou maior; padrão vazio. |
| `#:limits` | Registro de limites de recursos; padrão `#f`. |
| `#:strict?` | Exige a configuração estrita completa; padrão `#f`. |
| `#:supervise?` | Supervisor PID 1; padrão `#f`, habilitado automaticamente no modo estrito. |
| `#:teardown-timeout-ms` | Prazo entre TERM e KILL do supervisor, de 1 a 60000 ms; padrão 2000. |

O construtor de três argumentos `(container nome rootfs comando)` continua
compatível. A API C pública está documentada em [`c/esquema.h`](../c/esquema.h);
seu ciclo usual é configurar, chamar `esquema_spawn`, chamar `esquema_wait` e
liberar a configuração.

## Isolamento e modo estrito

A configuração padrão cria namespaces de usuário, montagem, PID, UTS, IPC,
rede e cgroup, troca a raiz com `pivot_root`, destaca a árvore de montagens
antiga e fornece um novo `/proc` e um `/dev` mínimo. O uid 0 dentro do namespace
é mapeado para o uid do usuário que iniciou o programa no host. As capabilities
são removidas e `PR_SET_NO_NEW_PRIVS` é ativado. O programa compartilha o kernel
Linux do host.

O modo de compatibilidade mantém o comportamento legado do seccomp e tenta
configurar cgroups e Landlock sem tornar essas duas camadas obrigatórias. O
modo estrito, também chamado **Fortress**, exige todos os namespaces, seccomp,
remoção de capabilities, Landlock, supervisão PID 1, uma política seccomp
tipada, pelo menos um limite de cgroup e um limite de arquivos abertos versão 1:

```scheme
(use-modules (esquema runtime) (esquema container))

(exit
 (run-container
  (make-container "worker" "/caminho/absoluto/para/rootfs"
                  '("/bin/sh" "-c" "echo isolado")
                  #:strict? #t
                  #:rootfs-ro? #t
                  #:limits (make-limits-v1 (* 256 1024 1024)
                                          128 50000 100000 1024))))
```

`make-limits-v1` recebe memória em bytes, número de processos, cota de CPU em
microssegundos, período da CPU em microssegundos e máximo de arquivos abertos.
O exemplo solicita 256 MiB, 128 processos, 50% de uma CPU e 1024 arquivos abertos.
`#f` deixa um limite individual de cgroup sem definição; o modo estrito exige
pelo menos um. O construtor `make-limits`, de quatro argumentos, não gerencia o
limite de arquivos abertos e não basta para o modo estrito. O construtor Scheme
fornece a política seccomp Fortress e o supervisor; chamadores C precisam
selecioná-los explicitamente.

A inicialização estrita é interrompida se falharem a delegação de cgroups, a
leitura de verificação dos limites, Landlock ou as operações de montagem
exigidas. Delegue os controladores solicitados ao cgroup do usuário que inicia
o programa; apenas montar cgroups v2 não basta. Uma execução em compatibilidade
não demonstra que o modo estrito funciona nesse host.

Outros limites da política:

- **Seccomp:** a versão 1 valida a arquitetura nativa, famílias de sockets,
  `io_uring` e tratamento de ioctl. Chamadas desconhecidas retornam `ENOSYS`;
  negações obrigatórias de chamadas perigosas encerram o processo. Por exemplo,
  `(make-seccomp-policy 'native '(unix) 'deny 'restricted)` seleciona sockets
  Unix e nega `io_uring`. `TIOCSTI` e `TIOCLINUX` continuam com negação fatal.
  ABIs não nativas, incluindo x32, são rejeitadas.
- **Landlock:** a regra básica restringe os acessos tratados à árvore da nova
  raiz. Não é uma política de permissões por diretório e não revoga descritores
  já abertos. A cobertura depende dos cabeçalhos usados na compilação e do
  kernel em execução; nem toda operação de metadados é coberta.
- **Descritores:** descritores herdados acima de 2 são fechados, exceto os
  listados em `#:preserve-fds`. Entrada, saída e erro padrão permanecem
  disponíveis. Cada descritor preservado é uma capacidade de acesso concedida
  explicitamente ao programa.
- **Arquivos abertos:** o limite versão 1 deve estar entre 16 e 1048576. Os
  limites flexível e rígido de `RLIMIT_NOFILE` são instalados e verificados
  antes da execução. Descritores preservados iguais ou superiores ao limite são
  rejeitados. O seccomp estrito também rejeita alteração de limites de recursos.
  A chamada direta de limite tem implementação para x86-64 e AArch64; em outras
  arquiteturas, falha sem executar o programa.
- **Montagens:** destinos bind rejeitam componentes vazios, `.` e `..` e
  travessia por links simbólicos. Montagens estritas exigem a API baseada em
  descritores. Raízes estritas somente para leitura exigem `mount_setattr`
  recursivo e verificação; o modo de compatibilidade pode usar uma remontagem
  mais limitada, que deixa montagens aninhadas graváveis.
- **Ciclo de vida:** o supervisor encaminha sinais ao grupo de processos do
  programa, recolhe descendentes e passa de TERM para KILL após o prazo.
  O registro de execuções com cgroup é compartilhado entre threads e limitado
  a 4096 registros ativos.

## Servir um site

Este exemplo voltado ao Guix usa o `httpd` do BusyBox e monta `/gnu/store`
somente para leitura, para disponibilizar o carregador e as bibliotecas:

```sh
guix shell -m manifest.scm -- make smoke
BUSYBOX="$(guix build busybox)/bin/busybox" \
  sh examples/build-web-rootfs.sh examples/rootfs-web
ESQ_PORT=8081 guix shell -m manifest.scm -- \
  env ESQUEMA_LIBDIR="$PWD" guile -L scheme examples/deploy-web.scm
```

Em outro terminal, execute `curl --fail http://127.0.0.1:8081/`. Coloque o
conteúdo em `examples/rootfs-web/www/`. A variável
`ESQ_ROOTFS=/caminho/absoluto/para/rootfs` substitui a raiz relativa ao script;
`ESQ_PORT` usa 8081 por padrão.

O exemplo omite o namespace de rede para usar a rede do host. Ele usa o modo de
compatibilidade e não atende à exigência de todos os namespaces do modo estrito.
Os limites de cgroup são aplicados quando possível. A montagem do store expõe
seu conteúdo legível. Um servidor estático pode dispensá-la se o rootfs for
autossuficiente e a lista de montagens também for ajustada.

Use uma porta sem privilégios permitida; `net.ipv4.ip_unprivileged_port_start`
controla esse limite no host. Um proxy reverso existente pode encaminhar HTTPS
público para a porta local escolhida. Configure endereço de escuta, regras de
acesso e TLS na implantação. O exemplo serve HTTP e pode escutar em todas as
interfaces do host.

## Guix e Shepherd

Com o canal `securityops` configurado e atualizado, instale o pacote usando
`guix install esquema`. Esse é um pacote de canal externo; sua existência não
significa que ele foi aceito no Guix oficial ou em outra distribuição.

`(esquema esquema-service)` exporta `esquema-service-type` e
`(esquema-configuration nome rootfs comando diretório-scheme)`. Ele cria um
serviço Shepherd com a configuração padrão de contêiner. Seus quatro campos não
expõem toda a política, os ajustes de rede do exemplo web nem seleção de conta.
Configure caminhos de busca de Scheme e da biblioteca e a conta de execução no
ambiente do serviço; a descrição do módulo não configura uma conta sem
privilégios. Para uma política explícita, supervisione um script Scheme que
construa o contêiner desejado e propague o status de saída.

## Testes

```sh
export ESQUEMA_TEST_SHELL="$(guix build bash-static:out)/bin/bash"
guix shell -m manifest.scm -- make check
guix shell -m manifest.scm -- make static
guix shell -m manifest.scm -- make sanitize
guix shell -m manifest.scm -- make test-perf
```

`check` executa testes C, funcionais e de segurança, cppcheck e regressões de
instalação com staging, prefixos personalizados e módulos Scheme compilados. `static`
executa o analisador do GCC. `sanitize` executa testes C com ASan e UBSan.
`test-perf` mede a sobrecarga de inicialização e vazamentos de recursos.
Consulte os alvos individuais com `make help`.

As suítes verificam negação de chamadas de sistema, fechamento de descritores,
travessia em montagens, limites, supervisão e falhas do modo estrito. Verificações
dependentes do kernel podem ser ignoradas ou falhar sem os requisitos do host;
examine a saída. Um teste de carregamento não demonstra todas as propriedades de
isolamento. Ao validar uma distribuição Linux, registre kernel, arquitetura,
dependências e resultados efetivos.

## Solução de problemas

| Sintoma | O que verificar |
| --- | --- |
| Guile não encontra `(esquema runtime)` | Use `guile -L scheme` no checkout ou acrescente o diretório instalado a `GUILE_LOAD_PATH`. |
| Não foi possível carregar `libesquema` | Execute `make smoke`; defina `ESQUEMA_LIBDIR` com o diretório da biblioteca correspondente. |
| Bash estático não encontrado | Defina `ESQUEMA_TEST_SHELL` com um Bash estático executável; ele não está no manifesto. |
| Falha de namespace ou status 91 | Verifique namespaces de usuário sem privilégios, configuração do kernel e restrições do host ou contêiner externo. |
| Falha de montagem ou status 94 | Verifique rootfs, destinos, propriedade dos arquivos e APIs exigidas pelo modo. |
| Falha na configuração estrita de cgroups | Delegue os controladores na subárvore cgroups v2 do chamador; examine `/proc/self/cgroup` e `/sys/fs/cgroup`. |
| Falha de Landlock ou status 99 | Verifique suporte do kernel e se o LSM Landlock está habilitado. |
| Falha no limite de arquivos ou status 101 | Verifique valor, descritores preservados e limite rígido atual do chamador. |
| Executável presente, mas status 127 | Verifique se o interpretador/carregador e as bibliotecas também existem no rootfs. |
| Site inacessível | Verifique `ESQ_PORT`, rede do host, firewall e se `httpd` está em execução. |

Os status de inicialização são diagnósticos da implementação; o programa pode
retornar os mesmos códigos. Use a mensagem de erro e a configuração para distingui-los.
