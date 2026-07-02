;;; website.scm — serve a static site from an isolated container.
;;;
;;; This needs a rootfs that actually contains the httpd binary. On Guix the
;;; idiomatic way is to bind the read-only store and point at a store path, or
;;; to `guix pack` a rootfs. The demo rootfs from build-rootfs.sh only has a
;;; static /bin/sh, so this file shows the *shape* of a real deployment.
(use-modules (esquema runtime)
             (esquema container))

(define web
  (make-container "website"
                  "examples/rootfs-web"
                  '("/bin/busybox" "httpd" "-f" "-p" "8080" "-h" "/www")
                  #:hostname   "website"
                  #:rootfs-ro? #t
                  ;; httpd wants a network; keep the private netns (loopback is
                  ;; brought up) or drop 'net from the list to share the host's.
                  #:namespaces '(user mount pid uts ipc net cgroup)
                  #:limits     (make-limits (* 128 1024 1024) 64 25000 100000)))

(run-container web)
