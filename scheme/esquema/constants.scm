;;; constants.scm — single source of namespace / clone flag constants.
;;;
;;; The NS-* values mirror the ESQUEMA_NS_* bitmask in c/esquema.h; the
;;; CLONE-NEW* values mirror <linux/sched.h> and are used by the granular
;;; esquema-unshare primitive and the low-level tests.
(define-module (esquema constants)
  #:use-module (srfi srfi-1)
  #:export (NS-USER NS-MOUNT NS-PID NS-UTS NS-IPC NS-NET NS-CGROUP NS-ALL
            namespaces->mask
            CLONE-NEWNS CLONE-NEWUTS CLONE-NEWIPC CLONE-NEWUSER
            CLONE-NEWPID CLONE-NEWNET CLONE-NEWCGROUP))

;; Esquema namespace bitmask (matches ESQUEMA_NS_* in the C header).
(define NS-USER   #b0000001)
(define NS-MOUNT  #b0000010)
(define NS-PID    #b0000100)
(define NS-UTS    #b0001000)
(define NS-IPC    #b0010000)
(define NS-NET    #b0100000)
(define NS-CGROUP #b1000000)
(define NS-ALL    #b1111111)

;; Raw CLONE_NEW* flags from <linux/sched.h> (verified on this kernel).
(define CLONE-NEWNS     #x00020000)
(define CLONE-NEWCGROUP #x02000000)
(define CLONE-NEWUTS    #x04000000)
(define CLONE-NEWIPC    #x08000000)
(define CLONE-NEWUSER   #x10000000)
(define CLONE-NEWPID    #x20000000)
(define CLONE-NEWNET    #x40000000)

(define %ns-alist
  `((user . ,NS-USER) (mount . ,NS-MOUNT) (pid . ,NS-PID) (uts . ,NS-UTS)
    (ipc . ,NS-IPC) (net . ,NS-NET) (cgroup . ,NS-CGROUP)))

;; Turn a list of namespace symbols into the C bitmask.
(define (namespaces->mask syms)
  (fold (lambda (s acc)
          (let ((p (assq s %ns-alist)))
            (unless p (error "esquema: unknown namespace" s))
            (logior acc (cdr p))))
        0 syms))
