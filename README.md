# Esquema - a Guile-native container runtime

**Esquema** is a minimal, security-first container runtime, built **natively in Scheme**.  
It integrates seamlessly with **GNU Guix** and **Shepherd**, enabling reproducible, isolated environments without the complexity of traditional container tooling.

Containers are **first-class Scheme objects**.  
Isolation is **explicit and fine-grained**.  
No OCI, no daemon, no YAML - just **pure, declarative Scheme**.

---

## Features

- **Rootless containers** - run securely without requiring root privileges.  
- **Linux namespaces** - full process, network, and filesystem isolation.  
- **Seccomp-BPF** - restrict syscalls for hardened security.  
- **cgroups v2** - resource management and limits.  
- **Shepherd supervision** - manage container lifecycles and processes reliably.  

---

## Why Esquema

Esquema offers a **different paradigm** from Docker, Podman, or FreeBSD jails:

| Feature                 | Esquema            | Docker/Podman      | Jails / LXC         | Guix Shell          |
|-------------------------|------------------|-----------------|------------------|------------------|
| Language-native          | Scheme            | No              | No               | Scheme            |
| Daemon-free              | ✅                | ❌               | ✅                | ✅                |
| Declarative configuration | ✅ (Scheme)       | ❌ (YAML/OCI)    | ❌               | ✅ (Guix)         |
| Fine-grained isolation   | ✅                | ✅               | ✅               | Limited           |
| Reproducible builds      | ✅                | Partial          | Partial           | ✅                |

Esquema **bridges the gap** between reproducible package management (Guix) and containerized, sandboxed execution. Developers can now define **secure, isolated environments directly in Scheme**, share them reproducibly, and run without heavy daemon dependencies.

---

## Getting Started

```scheme
(use-modules (esquema runtime)
             (esquema container)
             (esquema ffi))

(display (esquema-init))
(newline)

(define web
  (container "website"
             "examples/rootfs-web"
             '("/bin/busybox" "httpd" "-f" "-p" "8080" "-h" "/www")))

(run-sandboxed (lambda ()
                 (display "Hello from sandbox!\n")))

> Esquema empowers secure, reproducible, and declarative containerization for GNU Guix users, unlocking new workflows for development, CI/CD, and lightweight server deployments.
