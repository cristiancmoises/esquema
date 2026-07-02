;;; runtime.scm — high-level entry points.
(define-module (esquema runtime)
  #:use-module (ice-9 format)
  #:use-module (esquema ffi)
  #:use-module (esquema container)
  #:use-module (esquema sandbox)
  #:re-export (make-container container)
  #:export (run-container
            esquema-runtime-version))

(define (esquema-runtime-version) (esquema-version))

;;; Run a <container> to completion and return its exit status. This is the
;;; single supported way to launch an (untrusted) payload: it delegates to
;;; libesquema's esquema_spawn, which forks, isolates and execve()s.
(define (run-container c)
  (unless (container? c)
    (error "run-container: expected a <container>" c))
  (format #t "esquema: starting container ~s (rootfs ~a)~%"
          (container-name c) (container-rootfs c))
  (let ((rc (with-sandbox c)))
    (format #t "esquema: container ~s exited with status ~a~%"
            (container-name c) rc)
    rc))
