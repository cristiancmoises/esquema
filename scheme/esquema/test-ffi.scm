(define-module (esquema test-ffi)
  #:use-module (esquema ffi)
  #:use-module (ice-9 format))

(format #t "Testing Esquema…~%")

(define CLONE_NEWNS  #x00020000)
(define CLONE_NEWUTS #x04000000)
(define CLONE_NEWNET #x40000000)

(define flags
  (logior CLONE_NEWNS CLONE_NEWUTS CLONE_NEWNET))

(format #t "Calling unshare…~%")
(format #t "Result: ~a~%" (esquema-unshare flags))

(format #t "Dropping privileges…~%")
(format #t "Result: ~a~%" (esquema-drop-privs))

(format #t "Done ✔~%")
