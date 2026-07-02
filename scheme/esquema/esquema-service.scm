;;; esquema-service.scm — Shepherd/Guix service for supervising containers.
;;;
;;; Fixes over the original: imports srfi-9 for define-record-type and
;;; (guix gexp); never (object->string)s a live record (its #<...> form is
;;; unreadable) — instead it reconstructs the container inside the gexp from
;;; individually serialised fields, and matches run-container's single-record
;;; arity.
(define-module (esquema esquema-service)
  #:use-module (srfi srfi-9)
  #:use-module (guix gexp)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu packages guile)
  #:export (esquema-service-type
            esquema-configuration
            esquema-configuration?
            esquema-configuration-name
            esquema-configuration-rootfs
            esquema-configuration-command
            esquema-configuration-scheme-dir))

(define-record-type <esquema-configuration>
  (esquema-configuration name rootfs command scheme-dir)
  esquema-configuration?
  (name       esquema-configuration-name)        ; string
  (rootfs     esquema-configuration-rootfs)       ; string (absolute path)
  (command    esquema-configuration-command)      ; list of strings
  (scheme-dir esquema-configuration-scheme-dir))  ; where (esquema ...) lives

(define (esquema-shepherd config)
  (let ((name    (esquema-configuration-name config))
        (rootfs  (esquema-configuration-rootfs config))
        (command (esquema-configuration-command config))
        (scmdir  (esquema-configuration-scheme-dir config)))
    (list
     (shepherd-service
      (provision (list (string->symbol (string-append "esquema-" name))))
      (documentation "Esquema rootless container")
      (start
       #~(make-forkexec-constructor
          (list #$(file-append guile-3.0 "/bin/guile")
                "-L" #$scmdir "-c"
                (string-append
                 "(use-modules (esquema runtime)(esquema container))"
                 "(run-container (make-container "
                 #$(object->string name) " "
                 #$(object->string rootfs) " '"
                 #$(object->string command) "))"))))
      (stop #~(make-kill-destructor))
      (respawn? #t)))))

(define esquema-service-type
  (service-type
   (name 'esquema)
   (extensions
    (list (service-extension shepherd-root-service-type esquema-shepherd)))
   (description "Guile-native rootless container runtime")))
