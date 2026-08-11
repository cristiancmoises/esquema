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
            container-seccomp-policy
            container-drop-caps?
            container-rootfs-ro?
            container-strict?
            container-landlock?
            container-supervise?
            container-teardown-timeout-ms
            container-preserve-fds
            container-cgroup-name
            container-limits
            make-limits
            make-limits-v1
            limits?
            limits-memory-max
            limits-pids-max
            limits-cpu-quota
            limits-cpu-period
            limits-open-files-max
            make-seccomp-policy
            seccomp-policy?
            seccomp-policy-expected-arch
            seccomp-policy-socket-families
            seccomp-policy-io-uring
            seccomp-policy-ioctl
            fortress-seccomp-policy))

;;; Versioned policy inputs are symbols rather than raw libseccomp constants.
;;; The serializer in sandbox.scm maps these values to the stable v1 C ABI.
(define-record-type <seccomp-policy>
  (make-seccomp-policy expected-arch socket-families io-uring ioctl)
  seccomp-policy?
  (expected-arch  seccomp-policy-expected-arch)
  (socket-families seccomp-policy-socket-families)
  (io-uring       seccomp-policy-io-uring)
  (ioctl          seccomp-policy-ioctl))

(define (fortress-seccomp-policy)
  (make-seccomp-policy 'native '(unix inet inet6) 'deny 'restricted))

;;; Resource limits (all #f = unset). cpu-quota/period are microseconds.
;;; Keep the original four-argument constructor stable; the v1 constructor is
;;; additive and carries the policy-supplied RLIMIT_NOFILE value.
(define-record-type <limits>
  (%make-limits memory-max pids-max cpu-quota cpu-period open-files-max)
  limits?
  (memory-max limits-memory-max)
  (pids-max   limits-pids-max)
  (cpu-quota  limits-cpu-quota)
  (cpu-period limits-cpu-period)
  (open-files-max limits-open-files-max))

(define (make-limits memory-max pids-max cpu-quota cpu-period)
  (%make-limits memory-max pids-max cpu-quota cpu-period #f))

(define (make-limits-v1 memory-max pids-max cpu-quota cpu-period
                        open-files-max)
  (unless (and (integer? open-files-max)
               (<= 16 open-files-max 1048576))
    (error "limits v1: open-files-max must be 16..1048576"
           open-files-max))
  (%make-limits memory-max pids-max cpu-quota cpu-period open-files-max))

(define-record-type <container>
  (%make-container name rootfs command env mounts namespaces hostname
                   id-map seccomp? drop-caps? rootfs-ro? cgroup-name limits
                   strict? landlock? preserve-fds seccomp-policy supervise?
                   teardown-timeout-ms)
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
  (seccomp-policy container-seccomp-policy)
  (drop-caps?   container-drop-caps?)
  (rootfs-ro?   container-rootfs-ro?)
  (cgroup-name  container-cgroup-name)
  (limits       container-limits)      ; <limits> or #f
  (strict?      container-strict?)
  (landlock?    container-landlock?)
  (preserve-fds container-preserve-fds) ; explicit exec capability FDs
  (supervise?   container-supervise?)
  (teardown-timeout-ms container-teardown-timeout-ms))

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
                         (preserve-fds '())
                         (seccomp-policy #f)
                         (supervise? #f)
                         (teardown-timeout-ms 2000))
  (unless (string? rootfs) (error "container: rootfs must be a string" rootfs))
  (unless (and (list? command) (every string? command) (pair? command))
    (error "container: command must be a non-empty list of strings" command))
  (unless (and (list? preserve-fds)
               (every (lambda (fd) (and (integer? fd) (>= fd 3)))
                      preserve-fds))
    (error "container: preserve-fds must contain descriptors >= 3"
           preserve-fds))
  (when (and seccomp-policy (not (seccomp-policy? seccomp-policy)))
    (error "container: seccomp-policy must be a <seccomp-policy> or #f"
           seccomp-policy))
  (unless (and (integer? teardown-timeout-ms)
               (<= 1 teardown-timeout-ms 60000))
    (error "container: teardown timeout must be 1..60000 ms"
           teardown-timeout-ms))
  (when (and strict?
             (or (not (limits? limits))
                 (not (limits-open-files-max limits))))
    (error "container: strict mode requires a v1 open-files limit"
           limits))
  (when (and (limits? limits) (limits-open-files-max limits)
             (any (lambda (fd)
                    (>= fd (limits-open-files-max limits)))
                  preserve-fds))
    (error "container: preserved descriptor reaches open-files limit"
           preserve-fds (limits-open-files-max limits)))
  (let ((effective-policy
         (or seccomp-policy (and strict? (fortress-seccomp-policy)))))
    (%make-container name rootfs command env mounts namespaces hostname
                     id-map seccomp? drop-caps? rootfs-ro? cgroup-name limits
                     strict? landlock? preserve-fds effective-policy
                     (or strict? supervise?) teardown-timeout-ms)))

;;; Back-compat: the original three-argument positional constructor.
(define (container name rootfs command)
  (make-container name rootfs command))
