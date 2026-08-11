;;; functional.scm — SRFI-64 functional tests for Esquema.
;;;
;;; Verifies the library loads, containers launch, status propagates, and the
;;; core isolation primitives (PID/UTS/mount namespaces, rootless id map,
;;; env, bind mounts) actually take effect.
(use-modules (srfi srfi-64)
             (srfi srfi-13)
             (ice-9 format)
             (esquema ffi)
             (esquema container)
             (esquema constants)
             (esquema sandbox)
             (esquema tests harness))

(define (has? out sub) (and (string-contains out sub) #t))

(test-begin "esquema-functional")
(define runner (test-runner-current))

(define rootfs (make-test-rootfs))

;; ---- F1: library / FFI --------------------------------------------------
(test-equal "F1a esquema-init returns 42" 42 (esquema-init))
(test-assert "F1b version is a string" (string? (esquema-version)))
(test-assert "F1c version looks like 0.x" (string-prefix? "0." (esquema-version)))
(test-assert "F1d namespaces->mask maps all seven bits"
             (= NS-ALL (namespaces->mask '(user mount pid uts ipc net cgroup))))
(let ((legacy (make-limits #f #f #f #f))
      (v1 (make-limits-v1 #f #f #f #f 32)))
  (test-eqv "F1e legacy limits constructor keeps RLIMIT_NOFILE unset"
            #f (limits-open-files-max legacy))
  (test-eqv "F1f v1 limits constructor carries RLIMIT_NOFILE"
            32 (limits-open-files-max v1)))
(test-assert "F1g v1 limits reject an out-of-range RLIMIT_NOFILE"
  (catch #t
    (lambda () (make-limits-v1 #f #f #f #f 15) #f)
    (lambda _ #t)))
(test-assert "F1h strict Scheme policy requires a v1 RLIMIT_NOFILE"
  (catch #t
    (lambda ()
      (make-container "strict-no-nofile" rootfs (list "/bin/sh")
                      #:strict? #t
                      #:limits (make-limits 4096 #f #f #f))
      #f)
    (lambda _ #t)))
(test-assert "F1i preserved descriptors must be below RLIMIT_NOFILE"
  (catch #t
    (lambda ()
      (make-container "bad-preserved-fd" rootfs (list "/bin/sh")
                      #:limits (make-limits-v1 #f #f #f #f 32)
                      #:preserve-fds '(32))
      #f)
    (lambda _ #t)))

;; ---- F2: payload runs, status propagates --------------------------------
(call-with-values
    (lambda () (run-script rootfs "echo MARKER-OK; exit 0"))
  (lambda (rc out)
    (test-equal "F2a payload exits 0" 0 rc)
    (test-assert "F2b payload stdout captured" (has? out "MARKER-OK"))))

(call-with-values
    (lambda () (run-script rootfs "exit 42"))
  (lambda (rc out)
    (test-equal "F3 exit status propagates verbatim" 42 rc)))

;; ---- F4: PID namespace --------------------------------------------------
;; nullglob so an empty /proc yields NPROC=0. (dot delimiter avoids the
;; "NPROC=1" prefix matching "NPROC=12".) Also require the payload itself is
;; PID 1, proving /proc is a live, populated procfs for the new namespace.
(let ((hostpid (number->string (getpid))))
  (call-with-values
      (lambda ()
        (run-script rootfs
          (string-append
           "shopt -s nullglob; set -- /proc/[0-9]*; echo \"NPROC=$#.\"; "
           "[ -r /proc/1/status ] && echo PID1-OK; "
           "if [ -e /proc/" hostpid " ]; then echo HOSTPID-LEAK; else echo HOSTPID-HIDDEN; fi")))
    (lambda (rc out)
      (test-assert "F4a host pid invisible in container" (has? out "HOSTPID-HIDDEN"))
      (test-assert "F4b payload is PID 1 (populated procfs)" (has? out "PID1-OK"))
      (test-assert "F4c very few pids visible (isolated pid ns)"
                   (or (has? out "NPROC=1.") (has? out "NPROC=2.") (has? out "NPROC=3."))))))

;; ---- F5: UTS namespace --------------------------------------------------
;; Exact match against a unique hostname, with a negative control (no UTS ns
;; leaves the host's hostname untouched).
(let ((uniq (string-append "esq-uts-" (number->string (getpid)))))
  (define c (make-container uniq rootfs
                            (list "/bin/sh" "-c" "echo \"$(</proc/sys/kernel/hostname)\" > /esq-out")))
  (with-sandbox c)
  (let ((got (string-trim-both (file-content (string-append rootfs "/esq-out")))))
    (test-equal "F5a UTS ns sets the exact container hostname" uniq got))
  ;; Negative control: without the UTS namespace, hostname stays the host's.
  (define c2 (make-container uniq rootfs
                             (list "/bin/sh" "-c" "echo \"$(</proc/sys/kernel/hostname)\" > /esq-out")
                             #:namespaces '(user mount pid ipc net cgroup)))
  (with-sandbox c2)
  (let ((got2 (string-trim-both (file-content (string-append rootfs "/esq-out")))))
    (test-assert "F5b control: no UTS ns leaves host hostname (not ours)"
                 (not (string=? got2 uniq)))))

;; ---- F6: rootfs pivot ---------------------------------------------------
(call-with-values
    (lambda () (run-script rootfs "for f in /*; do echo ${f##*/}; done"))
  (lambda (rc out)
    (test-assert "F6a rootfs pivoted: /bin present" (has? out "bin"))
    (test-assert "F6b host-only dirs absent: no /home" (not (has? out "home")))
    (test-assert "F6c host-only dirs absent: no /gnu" (not (has? out "gnu")))))

;; ---- F7: rootless id map ------------------------------------------------
(let ((hostuid (number->string (getuid))))
  (call-with-values
      (lambda () (run-script rootfs "echo uid=$UID; echo \"$(</proc/self/uid_map)\""))
    (lambda (rc out)
      (test-assert "F7a in-namespace uid is 0 (root-in-ns)" (has? out "uid=0"))
      (test-assert "F7b uid_map maps 0 -> host uid" (has? out hostuid)))))

;; ---- F8: environment ----------------------------------------------------
(call-with-values
    (lambda () (run-script rootfs "echo GREETING=$GREETING"
                           #:env '(("PATH" . "/bin") ("GREETING" . "hola"))))
  (lambda (rc out)
    (test-assert "F8 custom environment variable passed through"
                 (has? out "GREETING=hola"))))

;; ---- F9: bind mount -----------------------------------------------------
(let* ((share (string-append rootfs "-share"))
       (_ (begin (mkdir share #o755)
                 (call-with-output-file (string-append share "/note.txt")
                   (lambda (p) (display "from-host" p))))))
  (mkdir (string-append rootfs "/mnt") #o755)
  (call-with-values
      (lambda () (run-script rootfs "echo \"$(</mnt/note.txt)\""
                             #:mounts (list (list share "mnt" #t))))
    (lambda (rc out)
      (test-assert "F9 read-only bind mount visible inside" (has? out "from-host"))))
  (system* "rm" "-rf" share))

(remove-rootfs rootfs)
(test-end "esquema-functional")
(exit (if (zero? (+ (test-runner-fail-count runner)
                    (test-runner-xpass-count runner))) 0 1))
