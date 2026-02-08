(use-modules (esquema container)
             (esquema runtime))

(define web
  (container
   "website"
   "examples/rootfs-web"
   '("/bin/busybox" "httpd" "-f" "-p" "8080" "-h" "/www")))

(run-container web)
