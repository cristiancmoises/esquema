(define-module (esquema sandbox)
  #:use-module (esquema ffi)
  #:export (with-sandbox))

;; Linux namespace flags (from sched.h)
(define CLONE_NEWNS   #x00020000)
(define CLONE_NEWUSER #x10000000)
(define CLONE_NEWPID  #x20000000)

;; Execution order:
;; 1. create user namespace (must be first)
;; 2. create other namespaces
;; 3. drop privileges
;; 4. run payload
(define (with-sandbox thunk)
  ;; Phase 1: user namespace
  (unless (= 0 (esquema-unshare CLONE_NEWUSER))
    (error "unshare userns failed"))

  ;; Phase 2: mount + pid namespaces
  (unless (= 0 (esquema-unshare
                (logior CLONE_NEWNS CLONE_NEWPID)))
    (error "unshare mount/pid failed"))

  ;; Phase 3: drop privileges
  (unless (= 0 (esquema-drop-privs))
    (error "drop-privs failed"))

  ;; Phase 4: execute payload
  (thunk))
