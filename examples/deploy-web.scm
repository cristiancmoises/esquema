;;; deploy-web.scm — serve examples/rootfs-web with busybox httpd inside an
;;; Esquema container, reachable on the host.
;;;
;;; Run (installed esquema on the profile, or via `guix shell … esquema guile`):
;;;   ESQ_PORT=81 guile examples/deploy-web.scm      # 81 needs the sysctl below
;;;   guile examples/deploy-web.scm                  # defaults to 8081 (rootless)
;;;
;;; Port <1024 is privileged: a rootless container can only bind it after
;;;   sudo sysctl -w net.ipv4.ip_unprivileged_port_start=81
;;;
;;; The container shares the host network namespace (no 'net in #:namespaces)
;;; so httpd is reachable at http://localhost:<port>/ — every OTHER isolation
;;; layer (user/mount/pid/uts/ipc/cgroup ns, pivot_root, caps drop, seccomp)
;;; is still on. /gnu/store is bind-mounted read-only so the dynamically-linked
;;; busybox finds its loader + libraries.
(use-modules (esquema runtime)
             (esquema container))

(define port (or (getenv "ESQ_PORT") "8081"))
(define rootfs "/home/berkeley/esquema/examples/rootfs-web")

(define web
  (make-container "esquema-web" rootfs
                  (list "/bin/httpd" "-f" "-v" "-p" port "-h" "/www")
                  #:hostname   "esquema-web"
                  #:namespaces '(user mount pid uts ipc cgroup) ; share host net -> reachable
                  #:mounts     '(("/gnu/store" "gnu/store" #t)) ; ro: busybox's libs
                  #:rootfs-ro? #f
                  #:seccomp?   #t
                  #:drop-caps? #t
                  #:limits     (make-limits (* 128 1024 1024) 64 #f #f)))

(format #t "esquema-web: busybox httpd serving /www on 0.0.0.0:~a~%" port)
(run-container web)
