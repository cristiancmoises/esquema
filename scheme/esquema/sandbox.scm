;;; sandbox.scm — marshal a <container> into libesquema and run it.
;;;
;;; The security-critical fork/unshare/pivot/drop/seccomp/execve sequence all
;;; happens inside libesquema's esquema_spawn (async-signal-safe C). Guile
;;; never runs code between fork and execve, which is what makes confining an
;;; untrusted payload from a multi-threaded interpreter safe.
(define-module (esquema sandbox)
  #:use-module (system foreign)
  #:use-module (srfi srfi-1)
  #:use-module (esquema ffi)
  #:use-module (esquema container)
  #:use-module (esquema constants)
  #:export (container->config
            with-sandbox
            spawn-container
            sandbox-run))

;;; Build a freshly-allocated esquema_config* from a <container>.
;;; Caller owns the pointer and must esquema-config-free it. If any build
;;; step throws (bad namespace symbol, non-string field, out-of-range limit),
;;; the partially-built config is freed before the error propagates.
(define (container->config c)
  (let ((cfg (esquema-config-new)))
    (when (eqv? cfg %null-pointer)
      (error "esquema: config allocation failed"))
    (catch #t
      (lambda () (fill-config! cfg c) cfg)
      (lambda (key . args)
        (esquema-config-free cfg)
        (apply throw key args)))))

(define (fill-config! cfg c)
    (define (checked stage rc)
      (unless (zero? rc)
        (error (string-append "esquema config failed: " stage)
               (esquema-strerror))))
    (checked "rootfs"
             (esquema-config-set-rootfs cfg (container-rootfs c)))
    (when (container-hostname c)
      (checked "hostname"
               (esquema-config-set-hostname cfg (container-hostname c))))
    (for-each (lambda (a) (checked "argument"
                                    (esquema-config-add-arg cfg a)))
              (container-command c))
    (for-each (lambda (kv)
                (checked "environment"
                         (esquema-config-add-env
                          cfg (string-append (car kv) "=" (cdr kv)))))
              (container-env c))
    (for-each (lambda (m)
                (checked "bind mount"
                         (esquema-config-add-bind
                          cfg (car m) (cadr m)
                          (and (pair? (cddr m)) (caddr m)))))
              (container-mounts c))
    (for-each (lambda (fd)
                (checked "preserved descriptor"
                         (esquema-config-preserve-fd cfg fd)))
              (container-preserve-fds c))
    (esquema-config-set-namespaces
     cfg (namespaces->mask (container-namespaces c)))
    (let ((idm (container-id-map c)))
      (when idm (esquema-config-set-id-map cfg (car idm) (cdr idm))))
    (esquema-config-set-seccomp cfg (container-seccomp? c))
    (let ((policy (container-seccomp-policy c)))
      (define (arch-value arch)
        (case arch
          ((native) 0)
          ((x86-64) 1)
          ((aarch64) 2)
          (else (error "esquema: unknown seccomp architecture" arch))))
      (define (socket-bit family)
        (case family
          ((unix) 1)
          ((inet) 2)
          ((inet6) 4)
          ((netlink) 8)
          ((vsock) 16)
          (else (error "esquema: unknown socket family" family))))
      (define (io-uring-value value)
        (case value
          ((deny) 0)
          ((allow) 1)
          (else (error "esquema: unknown io_uring policy" value))))
      (define (ioctl-value value)
        (case value
          ((none) 0)
          ((restricted) 1)
          ((legacy) 2)
          (else (error "esquema: unknown ioctl policy" value))))
      (when policy
        (let ((sockets (fold (lambda (family mask)
                               (logior mask (socket-bit family)))
                             0
                             (seccomp-policy-socket-families policy))))
          (checked "seccomp policy"
                   (esquema-config-set-seccomp-policy-v1
                    cfg
                    (arch-value (seccomp-policy-expected-arch policy))
                    sockets
                    (io-uring-value (seccomp-policy-io-uring policy))
                    (ioctl-value (seccomp-policy-ioctl policy)))))))
    (esquema-config-set-drop-caps cfg (container-drop-caps? c))
    (esquema-config-set-rootfs-ro cfg (container-rootfs-ro? c))
    (esquema-config-set-strict cfg (container-strict? c))
    (esquema-config-set-landlock cfg (container-landlock? c))
    (checked "supervisor"
             (esquema-config-set-supervisor
              cfg (container-supervise? c)
              (container-teardown-timeout-ms c)))
    (let ((lim (container-limits c))
          (cg  (container-cgroup-name c)))
      (when (or lim cg)
        (checked "cgroup name"
                 (esquema-config-set-cgroup-name
                  cfg (or cg (container-name c))))
        (when lim
          (when (limits-open-files-max lim)
            (checked "open-files limit"
                     (esquema-config-set-open-files-max
                      cfg (limits-open-files-max lim))))
          (when (limits-memory-max lim)
            (esquema-config-set-memory-max cfg (limits-memory-max lim)))
          (when (limits-pids-max lim)
            (esquema-config-set-pids-max cfg (limits-pids-max lim)))
          (when (and (limits-cpu-quota lim) (limits-cpu-period lim))
            (esquema-config-set-cpu-max cfg (limits-cpu-quota lim)
                                        (limits-cpu-period lim))))))
    cfg)

;;; Spawn a container and return its child pid (or raise on failure).
(define (spawn-container c)
  (let ((cfg (container->config c)))
    (dynamic-wind
      (lambda () #t)
      (lambda ()
        (let ((pid (esquema-spawn cfg)))
          (when (< pid 0)
            (error "esquema-spawn failed" (esquema-strerror)))
          pid))
      (lambda () (esquema-config-free cfg)))))

;;; Run a container to completion; return its exit status.
(define (with-sandbox c)
  (let ((pid (spawn-container c)))
    (let ((rc (esquema-wait pid)))
      (when (< rc 0)
        (error "esquema-wait failed" (esquema-strerror)))
      rc)))

;;; Alias kept for readability in scripts.
(define (sandbox-run c) (with-sandbox c))
