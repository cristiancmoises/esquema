;;; container.scm — the <container> value: a fully declarative sandbox spec.
(define-module (esquema container)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:export (make-container
            container                 ; back-compat positional constructor
            container?
            container-name
            container-rootfs
            container-command
            container-env
            container-mounts
            container-namespaces
            container-hostname
            container-id-map
            container-seccomp?
            container-drop-caps?
            container-rootfs-ro?
            container-strict?
            container-landlock?
            container-preserve-fds
            container-cgroup-name
            container-limits
            make-limits
            limits?
            limits-memory-max
            limits-pids-max
            limits-cpu-quota
            limits-cpu-period))

;;; Resource limits (all #f = unset). cpu-quota/period are microseconds.
(define-record-type <limits>
  (make-limits memory-max pids-max cpu-quota cpu-period)
  limits?
  (memory-max limits-memory-max)
  (pids-max   limits-pids-max)
  (cpu-quota  limits-cpu-quota)
  (cpu-period limits-cpu-period))

(define-record-type <container>
  (%make-container name rootfs command env mounts namespaces hostname
                   id-map seccomp? drop-caps? rootfs-ro? cgroup-name limits
                   strict? landlock? preserve-fds)
  container?
  (name         container-name)
  (rootfs       container-rootfs)
  (command      container-command)     ; list of strings (argv)
  (env          container-env)         ; alist ((\"KEY\" . \"VALUE\") ...)
  (mounts       container-mounts)      ; list of (src dst read-only?)
  (namespaces   container-namespaces)  ; list of symbols
  (hostname     container-hostname)
  (id-map       container-id-map)      ; (uid . gid) or #f -> current uid/gid
  (seccomp?     container-seccomp?)
  (drop-caps?   container-drop-caps?)
  (rootfs-ro?   container-rootfs-ro?)
  (cgroup-name  container-cgroup-name)
  (limits       container-limits)      ; <limits> or #f
  (strict?      container-strict?)
  (landlock?    container-landlock?)
  (preserve-fds container-preserve-fds)) ; explicit exec capability FDs

;;; Full keyword constructor with secure-by-default settings.
(define* (make-container name rootfs command
                         #:key
                         (env '())
                         (mounts '())
                         (namespaces '(user mount pid uts ipc net cgroup))
                         (hostname name)
                         (id-map #f)
                         (seccomp? #t)
                         (drop-caps? #t)
                         (rootfs-ro? #f)
                         (cgroup-name #f)
                         (limits #f)
                         (strict? #f)
                         (landlock? #t)
                         (preserve-fds '()))
  (unless (string? rootfs) (error "container: rootfs must be a string" rootfs))
  (unless (and (list? command) (every string? command) (pair? command))
    (error "container: command must be a non-empty list of strings" command))
  (unless (and (list? preserve-fds)
               (every (lambda (fd) (and (integer? fd) (>= fd 3)))
                      preserve-fds))
    (error "container: preserve-fds must contain descriptors >= 3"
           preserve-fds))
  (%make-container name rootfs command env mounts namespaces hostname
                   id-map seccomp? drop-caps? rootfs-ro? cgroup-name limits
                   strict? landlock? preserve-fds))

;;; Back-compat: the original three-argument positional constructor.
(define (container name rootfs command)
  (make-container name rootfs command))
