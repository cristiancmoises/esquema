;;; hello.scm — run a command inside a fully-isolated Esquema container.
;;;
;;; First build the demo rootfs:
;;;   examples/build-rootfs.sh examples/rootfs-min
;;; Then run this example:
;;;   guix shell -m manifest.scm -- \
;;;     env ESQUEMA_LIBDIR=$PWD guile -L scheme examples/hello.scm
(use-modules (esquema runtime)
             (esquema container))

(define here (dirname (dirname (current-filename))))   ; repo root

(define demo
  (make-container "demo"
                  (string-append here "/examples/rootfs-min")
                  (list "/bin/sh" "/hello.sh")
                  ;; Secure by default: all namespaces, seccomp on, caps dropped.
                  #:hostname "demo"
                  #:rootfs-ro? #t))

;; run-container forks, isolates and execve()s the payload, then waits.
(exit (run-container demo))
