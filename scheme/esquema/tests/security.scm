;;; security.scm — SRFI-64 isolation / escape-attempt tests.
;;;
;;; Each check pairs the sandbox behaviour (must block / must be isolated)
;;; with, where practical, a positive control (the same probe WITHOUT the
;;; relevant protection must reproduce the leak) so a sandbox that silently
;;; protects nothing is caught.
(use-modules (srfi srfi-64)
             (srfi srfi-13)
             (ice-9 format)
             (esquema ffi)
             (esquema container)
             (esquema sandbox)
             (esquema tests harness))

(define (has? out sub) (and (string-contains out sub) #t))
(define (count-substr out sub)
  (let loop ((i 0) (n 0))
    (let ((j (string-contains out sub i)))
      (if j (loop (+ j 1) (+ n 1)) n))))

(test-begin "esquema-security")
(define runner (test-runner-current))
(define rootfs (make-test-rootfs))

;; Read selected /proc/self/status fields (bash builtins only, no fork).
(define status-probe
  (string-append
   "while read -r k v _; do case $k in "
   "CapEff:|CapPrm:|CapBnd:|CapInh:|CapAmb:|NoNewPrivs:|Seccomp:) "
   "echo \"$k $v\";; esac; done < /proc/self/status"))

;; ---- S1: capabilities fully dropped ------------------------------------
(call-with-values
    (lambda () (run-script rootfs status-probe))
  (lambda (rc out)
    (test-assert "S1a effective caps empty"    (has? out "CapEff: 0000000000000000"))
    (test-assert "S1b permitted caps empty"    (has? out "CapPrm: 0000000000000000"))
    (test-assert "S1c bounding set empty"      (has? out "CapBnd: 0000000000000000"))
    (test-assert "S1d ambient caps empty"      (has? out "CapAmb: 0000000000000000"))
    ;; ---- S2: no-new-privs blocks setuid escalation ----
    (test-assert "S2 NoNewPrivs is set"        (has? out "NoNewPrivs: 1"))
    ;; ---- S3: seccomp filter is active (mode 2 = SECCOMP_MODE_FILTER) ----
    (test-assert "S3a seccomp filter active"   (has? out "Seccomp: 2"))))

;; S3 positive control: with seccomp disabled the field is 0.
(call-with-values
    (lambda () (run-script rootfs status-probe #:seccomp? #f))
  (lambda (rc out)
    (test-assert "S3b control: no filter when seccomp disabled"
                 (has? out "Seccomp: 0"))))

;; ---- S4: host PIDs invisible (with a live host sentinel) ---------------
(let ((sentinel (primitive-fork)))
  (if (zero? sentinel)
      (begin (sleep 30) (primitive-exit 0))
      (begin
        (call-with-values
            (lambda ()
              (run-script rootfs
                (string-append "if kill -0 " (number->string sentinel)
                               " 2>/dev/null; then echo REACHABLE; else echo UNREACHABLE; fi; "
                               "if [ -e /proc/" (number->string sentinel) " ]; then echo VISIBLE; else echo HIDDEN; fi")))
          (lambda (rc out)
            (test-assert "S4a host sentinel pid not in /proc" (has? out "HIDDEN"))
            (test-assert "S4b host sentinel not signalable"   (has? out "UNREACHABLE"))))
        (kill sentinel SIGTERM)
        (waitpid sentinel))))

;; ---- S5: host filesystem confidentiality -------------------------------
(let ((canary (string-append (or (getenv "TMPDIR") "/tmp")
                             "/esq-canary-" (number->string (getpid)))))
  (call-with-output-file canary (lambda (p) (display "TOP-SECRET" p)))
  (call-with-values
      (lambda ()
        (run-script rootfs
          (string-append "if [ -e " canary " ]; then echo LEAK; else echo SAFE; fi; "
                         "for d in etc home root gnu; do [ -e /$d ] && echo HOST-$d; done; true")))
    (lambda (rc out)
      (test-assert "S5a host canary file unreachable" (has? out "SAFE"))
      (test-assert "S5b no host /home leaked"          (not (has? out "HOST-home")))
      (test-assert "S5c no host /gnu store leaked"     (not (has? out "HOST-gnu")))))
  (delete-file canary))

;; Ambient descriptors bypass pathname and namespace checks because they are
;; already-open capabilities.  The negative proves default closure; the
;; positive proves that only an explicit descriptor grant survives exec.
(let* ((canary (string-append (or (getenv "TMPDIR") "/tmp")
                              "/esq-fd-canary-" (number->string (getpid))))
       (port #f)
       (leak-fd #f))
  (call-with-output-file canary
    (lambda (p) (display "AMBIENT-FD-SECRET\n" p)))
  (set! port (open-input-file canary))
  (set! leak-fd (dup (fileno port)))
  ;; Be explicit: this regression must not pass merely because Guile happened
  ;; to create a close-on-exec descriptor.
  (fcntl leak-fd F_SETFD 0)
  (let ((probe
         (string-append
          "if IFS= read -r -u " (number->string leak-fd)
          " value; then echo CAPABILITY:$value; else echo CLOSED; fi")))
    (call-with-values
        (lambda () (run-script rootfs probe))
      (lambda (rc out)
        (test-assert "S5d ambient inherited secret fd is closed"
                     (and (zero? rc) (has? out "CLOSED")
                          (not (has? out "AMBIENT-FD-SECRET"))))))
    (seek leak-fd 0 SEEK_SET)
    (call-with-values
        (lambda ()
          (run-script rootfs probe #:preserve-fds (list leak-fd)))
      (lambda (rc out)
        (test-assert "S5e explicitly allowlisted capability fd survives exec"
                     (and (zero? rc)
                          (has? out "CAPABILITY:AMBIENT-FD-SECRET"))))))
  (close-fdes leak-fd)
  (close-port port)
  (delete-file canary))

;; A preserved directory fd is a classic chroot/pivot escape primitive.  It is
;; intentionally delegated here to prove that the integrated Landlock layer
;; still rejects a *new* open beneath a host directory.  Disabling Landlock in
;; legacy mode is the positive control demonstrating that the attack is real.
(let* ((base (string-append (or (getenv "TMPDIR") "/tmp")
                            "/esq-landlock-canary-"
                            (number->string (getpid))))
       (secret (string-append base "/secret")))
  (mkdir base #o700)
  (call-with-output-file secret
    (lambda (p) (display "LANDLOCK-HOST-SECRET\n" p)))
  (let* ((dir-fd (open-fdes base O_RDONLY))
         (probe (string-append
                 "if IFS= read -r value < /proc/self/fd/"
                 (number->string dir-fd)
                 "/secret; then echo LEAK:$value; else echo DENIED; fi")))
    (fcntl dir-fd F_SETFD 0)
    (if (> (esquema-landlock-abi) 0)
        (call-with-values
            (lambda ()
              (run-script rootfs probe #:preserve-fds (list dir-fd)))
          (lambda (rc out)
            (test-assert "S5f Landlock denies new access via preserved host dirfd"
                         (and (zero? rc) (has? out "DENIED")
                              (not (has? out "LANDLOCK-HOST-SECRET"))))))
        (begin
          (format #t "BLOCKED S5f: running kernel has no Landlock ABI~%")
          (test-skip 1)
          (test-assert "S5f Landlock denies new access via preserved host dirfd"
                       #f)))
    (call-with-values
        (lambda ()
          (run-script rootfs probe #:preserve-fds (list dir-fd)
                      #:landlock? #f))
      (lambda (rc out)
        (test-assert "S5g control: explicit legacy no-Landlock mode exposes dirfd"
                     (and (zero? rc)
                          (has? out "LEAK:LANDLOCK-HOST-SECRET")))))
    (close-fdes dir-fd))
  (delete-file secret)
  (rmdir base))

;; ---- S6: network isolation ---------------------------------------------
;; With a private net namespace only loopback exists; the positive control
;; without NEWNET sees the host's interfaces.
(let ((count-ifaces "n=0; while read -r line; do case $line in *:*) n=$((n+1));; esac; done < /proc/net/dev; echo \"IFACES=$n.\""))
  (call-with-values
      (lambda () (run-script rootfs count-ifaces))
    (lambda (rc out)
      (test-assert "S6a only loopback in private netns" (has? out "IFACES=1."))))
  (call-with-values
      (lambda () (run-script rootfs count-ifaces
                             #:namespaces '(user mount pid uts ipc cgroup)))
    (lambda (rc out)
      (test-assert "S6b control: host interfaces visible without netns"
                   (and (not (has? out "IFACES=1.")) (has? out "IFACES="))))))

;; ---- S7: host mount table not leaked -----------------------------------
;; Compare the container's mount table to the host's: it must have its own
;; root + /proc, far fewer entries than the host, and none of the host's
;; distinctive mounts (the store, /home, host /proc entries).
(define (count-lines s)
  (let loop ((i 0) (n 0))
    (let ((j (string-index s #\newline i)))
      (if j (loop (+ j 1) (+ n 1)) (+ n (if (< i (string-length s)) 1 0))))))
(define host-mounts (file-content "/proc/self/mounts"))
(define host-mount-count (count-lines host-mounts))
(call-with-values
    (lambda () (run-script rootfs "echo \"$(</proc/self/mounts)\""))
  (lambda (rc out)
    (test-assert "S7a container has its own /proc mount" (has? out " /proc "))
    (test-assert "S7b container mount table far smaller than host's"
                 (< (count-lines out) (max 5 (quotient host-mount-count 2))))
    (test-assert "S7c host /gnu/store mount not leaked" (not (has? out "/gnu/store")))
    (test-assert "S7d host /home mount not leaked"      (not (has? out " /home ")))))

;; ---- S8: read-only rootfs enforced -------------------------------------
(test-eqv "S8a writing to a read-only rootfs fails"
          3 (run-status rootfs "echo x > /rotest 2>/dev/null || exit 3" #:rootfs-ro? #t))
(test-eqv "S8b control: writable rootfs allows the write"
          0 (run-status rootfs "echo x > /rotest 2>/dev/null && exit 0" #:rootfs-ro? #f))

;; ---- S9: cgroup name traversal rejected --------------------------------
(test-eqv "S9a traversal cgroup name rejected"  -1 (esquema-enter-cgroup "../escape"))
(test-eqv "S9b slash in cgroup name rejected"   -1 (esquema-enter-cgroup "a/b"))

;; ---- S10: normal lifecycle teardown -----------------------------------
(let* ((c (make-container "teardown" rootfs
                          (list "/bin/sh" "-c" "exit 0")
                          #:env '(("PATH" . "/bin"))))
       (pid (spawn-container c))
       (rc (esquema-wait pid)))
  (test-eqv "S10a normal payload exits cleanly" 0 rc)
  (test-assert "S10b setup/reaper process is gone after wait"
               (not (file-exists?
                     (string-append "/proc/" (number->string pid))))))

(remove-rootfs rootfs)
(test-end "esquema-security")
(exit (if (zero? (+ (test-runner-fail-count runner)
                    (test-runner-xpass-count runner))) 0 1))
