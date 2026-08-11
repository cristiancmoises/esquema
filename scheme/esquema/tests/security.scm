;;; security.scm — SRFI-64 isolation / escape-attempt tests.
;;;
;;; Each check pairs the sandbox behaviour (must block / must be isolated)
;;; with, where practical, a positive control (the same probe WITHOUT the
;;; relevant protection must reproduce the leak) so a sandbox that silently
;;; protects nothing is caught.
(use-modules (srfi srfi-64)
             (srfi srfi-1)
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

(define (wait-for-path path attempts)
  (let loop ((remaining attempts))
    (cond ((file-exists? path) #t)
          ((zero? remaining) #f)
          (else (usleep 10000) (loop (- remaining 1))))))

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

;; ---- S11: bind destinations are lexical and fd-resolved ---------------
(test-assert "S11a Scheme path rejects an absolute bind destination"
  (catch #t
    (lambda ()
      (let ((cfg (container->config
                  (make-container "bad-bind" rootfs '("/bin/sh")
                                  #:mounts (list (list "/tmp" "/escape" #t))))))
        (esquema-config-free cfg)
        #f))
    (lambda _ #t)))
(test-assert "S11b Scheme path rejects bind traversal"
  (catch #t
    (lambda ()
      (let ((cfg (container->config
                  (make-container "bad-bind" rootfs '("/bin/sh")
                                  #:mounts
                                  (list (list "/tmp" "tmp/../escape" #t))))))
        (esquema-config-free cfg)
        #f))
    (lambda _ #t)))

(let* ((outside (string-append rootfs "-outside"))
       (source (string-append rootfs "-bind-source"))
       (link (string-append rootfs "/escape-link"))
       (canary (string-append outside "/canary")))
  (mkdir outside #o700)
  (mkdir source #o700)
  (call-with-output-file canary (lambda (p) (display "UNCHANGED" p)))
  (symlink outside link)
  (let ((rc (run-status rootfs "exit 0"
                        #:mounts (list (list source "escape-link" #t)))))
    (test-eqv "S11c symlink destination fails before payload exec" 94 rc)
    (test-equal "S11d rejected bind did not alter outside target"
                "UNCHANGED" (file-content canary)))
  (delete-file link)
  (delete-file canary)
  (rmdir outside)
  (rmdir source))

;; A procfs fd entry is a magiclink.  It must not be accepted merely because
;; it lexically sits below the configured root.
(test-eqv "S11e procfs magiclink bind destination is rejected"
          94
          (run-status rootfs "exit 0"
                      #:mounts (list (list "/tmp" "proc/self/fd/0" #t))))

;; ---- S12: typed seccomp is usable from declarative Scheme -------------
(test-eqv "S12 Fortress seccomp policy executes an ordinary payload"
          0
          (run-status rootfs "exit 0"
                      #:seccomp-policy (fortress-seccomp-policy)))

;; ---- S12b: policy-supplied RLIMIT_NOFILE reaches the real payload -------
;; Compatibility seccomp deliberately retains setrlimit/prlimit64.  The
;; installed hard value independently prevents a raise; strict payloads also
;; receive a seccomp kill rule, covered by the C primitive suite.
(test-eqv "S12b RLIMIT_NOFILE is read back and an attempted raise fails"
          0
          (run-status
           rootfs
           "[ \"$(ulimit -n)\" = 32 ] || exit 21; ulimit -n 33 2>/dev/null && exit 22; [ \"$(ulimit -n)\" = 32 ]"
           #:limits (make-limits-v1 #f #f #f #f 32)))

;; ---- S13: PID-1 supervision and bounded teardown ----------------------
(let* ((ready (string-append rootfs "/signal-ready"))
       (seen (string-append rootfs "/signal-seen"))
       (c (make-container
           "signal-forward" rootfs
           (list "/bin/sh" "-c"
                 "trap 'echo FORWARDED > /signal-seen; exit 23' TERM; echo READY > /signal-ready; while :; do read -t 1 _ || :; done")
           #:env '(("PATH" . "/bin"))
           #:seccomp-policy (fortress-seccomp-policy)
           #:supervise? #t
           #:teardown-timeout-ms 250))
       (pid (spawn-container c)))
  (test-assert "S13a supervised payload reaches ready state"
               (wait-for-path ready 300))
  (kill pid SIGTERM)
  (let ((rc (esquema-wait pid)))
    (test-eqv "S13b TERM is forwarded to the payload" 23 rc)
    (test-assert "S13c payload observed the forwarded signal"
                 (and (file-exists? seen)
                      (has? (file-content seen) "FORWARDED")))
    (test-assert "S13d supervisor/setup process is gone"
                 (not (file-exists?
                       (string-append "/proc/" (number->string pid))))))
  (when (file-exists? ready) (delete-file ready))
  (when (file-exists? seen) (delete-file seen)))

(let* ((ready (string-append rootfs "/teardown-ready"))
       (c (make-container
           "bounded-teardown" rootfs
           (list "/bin/sh" "-c"
                 "trap '' TERM; echo READY > /teardown-ready; while :; do read -t 1 _ || :; done")
           #:env '(("PATH" . "/bin"))
           #:seccomp-policy (fortress-seccomp-policy)
           #:supervise? #t
           #:teardown-timeout-ms 100))
       (pid (spawn-container c)))
  (test-assert "S13e TERM-ignoring payload reaches ready state"
               (wait-for-path ready 300))
  (let ((start (get-internal-real-time)))
    (kill pid SIGTERM)
    (let* ((rc (esquema-wait pid))
           (elapsed (/ (- (get-internal-real-time) start)
                       internal-time-units-per-second)))
      (test-eqv "S13f TERM-ignoring payload is force-killed" 137 rc)
      (test-assert "S13g forced teardown remains bounded"
                   (< elapsed 3))))
  (when (file-exists? ready) (delete-file ready)))

;; The primary payload exits while an ignored-TERM descendant remains. As PID
;; 1, the supervisor adopts it, escalates after the bound, reaps it, and only
;; then returns the primary status.
(let* ((ready (string-append rootfs "/orphan-ready"))
       (c (make-container
           "orphan-reap" rootfs
           (list "/bin/sh" "-c"
                 "(trap '' TERM; while :; do read -t 1 _ || :; done) & echo READY > /orphan-ready; exit 7")
           #:env '(("PATH" . "/bin"))
           #:seccomp-policy (fortress-seccomp-policy)
           #:supervise? #t
           #:teardown-timeout-ms 100))
       (pid (spawn-container c))
       (rc (esquema-wait pid)))
  (test-eqv "S13h supervisor preserves primary status after orphan reap" 7 rc)
  (test-assert "S13i adopted descendant and namespace are fully reaped"
               (and (file-exists? ready)
                    (not (file-exists?
                          (string-append "/proc/" (number->string pid))))))
  (when (file-exists? ready) (delete-file ready)))

;; The launcher does not return the setup pid until its signal relay is live.
;; Therefore even a stop issued immediately after spawn must reach the future
;; PID-1 supervisor instead of killing A and leaving an untracked cell behind.
(let* ((c (make-container
           "immediate-stop" rootfs
           (list "/bin/sh" "-c"
                 "while :; do read -t 1 _ || :; done")
           #:env '(("PATH" . "/bin"))
           #:seccomp-policy (fortress-seccomp-policy)
           #:supervise? #t
           #:teardown-timeout-ms 100))
       (pid (spawn-container c)))
  (kill pid SIGTERM)
  (let ((rc (esquema-wait pid)))
    (test-assert "S13j immediate TERM is relayed or bounded-killed"
                 (or (= rc 143) (= rc 137)))
    (test-assert "S13k immediate stop leaves no setup process"
                 (not (file-exists?
                       (string-append "/proc/" (number->string pid)))))))

;; ---- S14: more than the historical 64 concurrent launches ------------
(let* ((count 72)
       (indexes (iota count))
       (ready-path
        (lambda (i) (string-append rootfs "/concurrent-" (number->string i))))
       (pids
        (map (lambda (i)
               (spawn-container
                (make-container
                 (string-append "concurrent-" (number->string i)) rootfs
                 (list "/bin/sh" "-c"
                       (string-append "echo READY > /concurrent-"
                                      (number->string i)
                                      "; kill -STOP $$; exit 0"))
                 #:env '(("PATH" . "/bin")))))
             indexes)))
  (test-assert "S14a 72 containers run concurrently"
    (let loop ((remaining 500))
      (cond ((every (lambda (i) (file-exists? (ready-path i))) indexes) #t)
            ((zero? remaining) #f)
            (else (usleep 10000) (loop (- remaining 1))))))
  (for-each (lambda (pid) (kill pid SIGCONT)) pids)
  (let ((statuses (map esquema-wait pids)))
    (test-assert "S14b all 72 concurrent payloads exit cleanly"
                 (every zero? statuses))
    (test-assert "S14c all 72 setup processes are cleaned up"
      (every (lambda (pid)
               (not (file-exists?
                     (string-append "/proc/" (number->string pid)))))
             pids)))
  (for-each (lambda (i)
              (let ((path (ready-path i)))
                (when (file-exists? path) (delete-file path))))
            indexes))

(remove-rootfs rootfs)
(test-end "esquema-security")
(exit (if (zero? (+ (test-runner-fail-count runner)
                    (test-runner-xpass-count runner))) 0 1))
