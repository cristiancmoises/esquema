;;; test-ffi.scm — quick manual FFI smoke check.
;;;
;;; Honest, non-false-positive checks that are safe to run from the live
;;; (multi-threaded) Guile process: it does NOT try to unshare a user
;;; namespace here (that requires the single-threaded child that
;;; esquema_spawn forks). For the full functional/security suite run
;;;   make check
;;; which exercises real isolation.
(define-module (esquema test-ffi)
  #:use-module (esquema ffi)
  #:use-module (esquema constants)
  #:use-module (ice-9 format))

(define failures 0)
(define (check name ok?)
  (format #t "~a ~a~%" (if ok? "ok  " "FAIL") name)
  (unless ok? (set! failures (+ failures 1))))

(format #t "Esquema FFI smoke (version ~a)~%" (esquema-version))

(check "esquema-init returns 42" (= 42 (esquema-init)))
(check "esquema-version is a string" (string? (esquema-version)))
(check "esquema-unshare rejects a disallowed flag (EINVAL)"
       (= -1 (esquema-unshare #x00000100)))   ; CLONE_VM: not permitted
(check "esquema-enter-cgroup rejects a traversal name"
       (= -1 (esquema-enter-cgroup "../evil")))

(format #t "~%~a check(s) failed~%" failures)
(exit (if (zero? failures) 0 1))
