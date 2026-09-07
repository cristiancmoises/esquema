# Esquema — a Guile-native container runtime

[English guide](docs/guide.md) · [Português brasileiro](#português-brasileiro) ·
[Guia completo em pt-BR](docs/guide.pt-BR.md)

Esquema runs programs in rootless Linux containers described as Scheme values.
Its Guile API calls a C library that sets up namespaces, filesystem isolation,
capability dropping and seccomp before executing the payload. No daemon is
required. Guix and Shepherd integration is included; the runtime can also be
built and installed directly on Linux.

## Requirements

- Linux with unprivileged user namespaces and seccomp enabled. The version-1
  resource policy implements x86-64 and AArch64; kernel features and local
  permissions also determine which configurations can run.
- Guile 3.0, a GNU-compatible C toolchain, GNU Make, `pkg-config`, libseccomp
  development files, and Linux UAPI headers including Landlock.
- A root filesystem containing the payload, its loader and its libraries.
  The demo and integration tests use **statically linked Bash**.
- Strict mode additionally needs working Landlock, delegated cgroups v2
  controllers and the required modern mount APIs. See the
  [operating guide](docs/guide.md#isolation-and-strict-mode).

Esquema uses Linux-specific APIs. BSD, macOS and Windows need a Linux VM to run
it; native support for those kernels is not implemented.

## Build and run

Run these commands from the repository root:

```sh
guix shell -m manifest.scm -- make smoke
export ESQUEMA_TEST_SHELL="$(guix build bash-static:out)/bin/bash"
guix shell -m manifest.scm -- sh examples/build-rootfs.sh examples/rootfs-min
guix shell -m manifest.scm -- env ESQUEMA_LIBDIR="$PWD" \
  guile -L scheme examples/hello.scm
```

The manifest selects dependencies from your current Guix channels; it does not
pin a channel revision. Record and pin the channels as well when reproducing a
build. `make smoke` checks library loading, while `hello.scm` launches an actual
container.

On a Linux system with the development dependencies already installed:

```sh
make smoke
make install PREFIX="$HOME/.local"
export GUILE_LOAD_PATH="$HOME/.local/share/guile/site/3.0${GUILE_LOAD_PATH:+:$GUILE_LOAD_PATH}"
guile -c '(use-modules (esquema runtime)) (display (esquema-runtime-version)) (newline)'
```

For package staging, custom directories and removal, see
[installation](docs/guide.md#installation).

## Describe a container

```scheme
(use-modules (esquema runtime) (esquema container))

(define demo
  (make-container "demo" "/absolute/path/to/rootfs"
                  '("/bin/sh" "-c" "echo Hello from Esquema")
                  #:rootfs-ro? #t))

(exit (run-container demo))
```

`run-container` waits and returns the exit status. The rootfs must already
contain `/bin/sh` and its dependencies. The default constructor enables all
seven namespaces, seccomp, capability dropping and an attempt to apply
Landlock. It leaves the rootfs writable unless `#:rootfs-ro? #t` is supplied.
Cgroup limits are best-effort in compatibility mode.

For mandatory limits, use `#:strict? #t` with `make-limits-v1`. Strict mode
requires the requested protections and aborts if they cannot be established;
the Scheme constructor supplies the typed seccomp policy and PID-1 supervisor.
See [a complete strict configuration](docs/guide.md#isolation-and-strict-mode).
All containers share the host Linux kernel, so this is not a VM boundary.

The [web example](docs/guide.md#serve-a-website) serves the included website on
port 8081. It deliberately shares the host network and uses compatibility mode;
it is not a strict configuration.

## Test

```sh
export ESQUEMA_TEST_SHELL="$(guix build bash-static:out)/bin/bash"
guix shell -m manifest.scm -- make check
guix shell -m manifest.scm -- make static
guix shell -m manifest.scm -- make sanitize
guix shell -m manifest.scm -- make test-perf
```

`check` runs C, functional and security tests, cppcheck, and installation
regressions with staged/custom prefixes and compiled Scheme modules. `sanitize` runs
the C tests with ASan and UBSan; `test-perf` measures startup and checks for
leaks. Integration tests require a host that permits the relevant namespace
operations. Performance depends on the host and configuration; the benchmark
reports measurements for the machine where it runs.

See the guide for [configuration and security boundaries](docs/guide.md),
[troubleshooting](docs/guide.md#troubleshooting), and
[Guix/Shepherd integration](docs/guide.md#guix-and-shepherd).

## Português brasileiro

O **Esquema** executa programas em contêineres Linux sem exigir root, descritos
como valores Scheme. A API em Guile usa uma biblioteca C para configurar
namespaces, isolamento do sistema de arquivos, remoção de capabilities e
seccomp antes de executar o programa. Não precisa de daemon. Há integração com
Guix e Shepherd e instalação direta em distribuições Linux.

### Requisitos e início rápido

Use Linux com namespaces de usuário sem privilégios e seccomp habilitados,
Guile 3.0, compilador C compatível com GNU, GNU Make, `pkg-config`, arquivos de
desenvolvimento do libseccomp e cabeçalhos Linux com Landlock. Os exemplos e os
testes de integração precisam de **Bash estaticamente vinculado**. A política de
recursos versão 1 implementa x86-64 e AArch64; os recursos do kernel e as
permissões do sistema também precisam ser compatíveis.

Na raiz do repositório:

```sh
guix shell -m manifest.scm -- make smoke
export ESQUEMA_TEST_SHELL="$(guix build bash-static:out)/bin/bash"
guix shell -m manifest.scm -- sh examples/build-rootfs.sh examples/rootfs-min
guix shell -m manifest.scm -- env ESQUEMA_LIBDIR="$PWD" \
  guile -L scheme examples/hello.scm
```

O manifesto usa os canais Guix atuais; ele não fixa suas revisões. Registre e
fixe também os canais para reproduzir a compilação. Em outra distribuição
Linux, com as dependências instaladas, use `make smoke` e
`make install PREFIX="$HOME/.local"`; o
[guia de instalação](docs/guide.pt-BR.md#instalação) explica os caminhos do Guile
e a preparação de pacotes.

### Isolamento e operação

Por padrão, `make-container` habilita os sete namespaces, seccomp, remoção de
capabilities e uma tentativa de aplicar Landlock. A raiz permite escrita até
que você use `#:rootfs-ro? #t`. No modo de compatibilidade, os limites de cgroup
são aplicados quando há delegação disponível, sem garantia obrigatória.

Para exigir os limites e as proteções, use `#:strict? #t` com `make-limits-v1`.
Esse modo exige Landlock, controladores cgroups v2 delegados e as APIs de
montagem necessárias; a inicialização é interrompida se os requisitos não
puderem ser atendidos. Os contêineres compartilham o kernel Linux do host.
BSD, macOS e Windows precisam de uma VM Linux; não há suporte nativo a esses
kernels.

O [tutorial do site](docs/guide.pt-BR.md#servir-um-site) usa a porta 8081 e
compartilha a rede do host. Ele usa o modo de compatibilidade. Para validar o
projeto, execute `guix shell -m manifest.scm -- make check` com a variável
`ESQUEMA_TEST_SHELL` definida conforme o exemplo acima.

Consulte o [guia completo em português](docs/guide.pt-BR.md) para a configuração
estrita, a API, a instalação, os testes e a solução de problemas.

## License / Licença

Esquema first-party source is available under either `AGPL-3.0-or-later` or a
separate signed commercial agreement. The commercial notice does not itself
grant proprietary-use rights and does not relicense GNU Guix, Guile, Linux,
libseccomp, libc, or other dependencies.

O código próprio do Esquema está disponível sob `AGPL-3.0-or-later` ou mediante
um contrato comercial separado e assinado. O aviso comercial, por si só, não
concede direitos de uso proprietário nem altera as licenças das dependências.

See / Consulte [LICENSING.md](LICENSING.md),
[LICENSING.pt-BR.md](LICENSING.pt-BR.md), [NOTICE](NOTICE),
[LICENSE](LICENSE), and [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL).
