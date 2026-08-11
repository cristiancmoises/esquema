;;; harness.scm — shared helpers for the Esquema test suites.
;;;
;;; Builds a self-contained test rootfs from a statically-linked shell (so
;;; no /gnu/store bind is needed) and runs scripts inside a container,
;;; capturing their stdout/stderr and exit status.
(define-module (esquema tests harness)
  #:use-module (srfi srfi-13)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 textual-ports)
  #:use-module (ice-9 format)
  #:use-module (esquema container)
  #:use-module (esquema sandbox)
  #:export (find-static-shell
            make-test-rootfs
            remove-rootfs
            run-script
            run-script/ns
            run-status
            file-content
            SIGSYS))

(define SIGSYS 31)

;; Locate a statically-linked bash in the store (or $ESQUEMA_TEST_SHELL).
(define (find-static-shell)
  (or (getenv "ESQUEMA_TEST_SHELL")
      (let* ((store "/gnu/store")
             (cands (or (scandir store
                                  (lambda (n) (string-contains n "bash-static")))
                        '())))
        (let loop ((cs cands))
          (cond ((null? cs) #f)
                ((let ((p (string-append store "/" (car cs) "/bin/bash")))
                   (and (file-exists? p) p)))
                (else (loop (cdr cs))))))))

(define %counter 0)
(define (make-temp-dir prefix)
  (let loop ()
    (set! %counter (+ %counter 1))
    (let ((d (format #f "~a/~a-~a-~a"
                     (or (getenv "TMPDIR") "/tmp") prefix (getpid) %counter)))
      (catch 'system-error
        (lambda () (mkdir d #o700) d)
        (lambda _ (loop))))))

;; Build a minimal rootfs containing /bin/sh (static bash) and the standard
;; mount points. Returns the absolute rootfs path.
(define (make-test-rootfs)
  (let ((sh (find-static-shell))
        (base (make-temp-dir "esq-rootfs")))
    (unless sh (error "harness: no static bash found; set ESQUEMA_TEST_SHELL"))
    (for-each (lambda (d) (mkdir (string-append base "/" d) #o755))
              '("bin" "proc" "dev" "tmp" "etc"))
    (copy-file sh (string-append base "/bin/sh"))
    (chmod (string-append base "/bin/sh") #o755)
    base))

(define (remove-rootfs base)
  (when (and base (file-exists? base))
    (system* "rm" "-rf" base)))

(define (file-content path)
  (if (file-exists? path)
      (call-with-input-file path get-string-all)
      ""))

;; Run SCRIPT (a /bin/sh -c string) inside a container built on ROOTFS.
;; Returns (values exit-status output-string). Output is captured by
;; redirecting into a file at the rootfs root (readable on the host after).
(define* (run-script rootfs script
                     #:key
                     (namespaces '(user mount pid uts ipc net cgroup))
                     (seccomp? #t)
                     (drop-caps? #t)
                     (strict? #f)
                     (landlock? #t)
                     (env '(("PATH" . "/bin")))
                     (mounts '())
                     (preserve-fds '()))
  (let* ((outfile "/esq-out")
         (wrapped (string-append "( " script " ) > " outfile " 2>&1"))
         (c (make-container "test" rootfs
                            (list "/bin/sh" "-c" wrapped)
                            #:namespaces namespaces
                            #:seccomp? seccomp?
                            #:drop-caps? drop-caps?
                            #:strict? strict?
                            #:landlock? landlock?
                            #:env env
                            #:mounts mounts
                            #:preserve-fds preserve-fds))
         (rc (with-sandbox c))
         (out (file-content (string-append rootfs outfile))))
    (values rc out)))

;; Like run-script but returns only the output (status ignored).
(define* (run-script/ns rootfs script #:key (namespaces '(user mount pid uts ipc net cgroup)))
  (call-with-values
      (lambda () (run-script rootfs script #:namespaces namespaces))
    (lambda (rc out) out)))

;; Run SCRIPT with NO output redirection (so it works on a read-only rootfs);
;; returns only the exit status. Exposes rootfs-ro?/seccomp?/namespaces so
;; tests can build negative and positive controls.
(define* (run-status rootfs script
                     #:key
                     (namespaces '(user mount pid uts ipc net cgroup))
                     (seccomp? #t)
                     (drop-caps? #t)
                     (rootfs-ro? #f)
                     (strict? #f)
                     (landlock? #t)
                     (env '(("PATH" . "/bin")))
                     (mounts '())
                     (preserve-fds '()))
  (with-sandbox
   (make-container "test" rootfs (list "/bin/sh" "-c" script)
                   #:namespaces namespaces
                   #:seccomp? seccomp?
                   #:drop-caps? drop-caps?
                   #:rootfs-ro? rootfs-ro?
                   #:strict? strict?
                   #:landlock? landlock?
                   #:env env
                   #:mounts mounts
                   #:preserve-fds preserve-fds)))
