# Esquema - a Guile-native container runtime

Esquema is a minimal, security-first container runtime designed
to integrate cleanly with GNU Guix and Shepherd.

Containers are Scheme objects.
Isolation is explicit.
No OCI, no daemon, no YAML.

#### Features:
- rootless containers
- Linux namespaces
- seccomp-bpf
- cgroups v2
- Shepherd supervision