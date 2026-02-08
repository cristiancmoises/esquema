;; scheme/esquema/runtime.scm
(define-module (esquema runtime)
  #:use-module (ice-9 posix)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-1)
  #:use-module (esquema ffi)
  #:use-module (esquema sandbox)
  #:export (run-container
           run-sandboxed
           current-sandbox-state))

;; Global variable to hold sandbox state
(define current-sandbox-state #f)

;; Function to run a container
(define (run-container name rootfs command)
  (let ((c (container name rootfs command)))
    (set! current-sandbox-state c)
    c))

;; Function to run code inside the sandbox
(define (run-sandboxed proc)
  (if current-sandbox-state
      (let ((c current-sandbox-state))
        ;; Here you can call your FFI functions to actually enter the sandbox
        (format #t "Running in sandbox: ~a~%" (container-name c))
        (proc))
      (error "No sandbox initialized")))

;; Initialize runtime
(define (esquema-init)
  ;; Just a placeholder to show that runtime loaded successfully
  42)
