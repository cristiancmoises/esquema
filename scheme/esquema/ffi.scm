(define-module (esquema ffi)
  #:use-module (system foreign)
  #:use-module (system foreign-library)
  #:export (esquema-init
            esquema-unshare
            esquema-drop-privs
            esquema-apply-seccomp))

(define libesquema
  (load-foreign-library
   (string-append (getcwd) "/libesquema.so")))

(define (c-func name return args)
  (pointer->procedure
   return
   (foreign-library-pointer libesquema name)
   args))

(define esquema-init
  (c-func "esquema_init" int '()))

(define esquema-unshare
  (c-func "esquema_unshare" int (list int)))

(define esquema-drop-privs
  (c-func "esquema_drop_privs" int '()))

(define esquema-apply-seccomp
  (c-func "esquema_apply_seccomp" int '()))
