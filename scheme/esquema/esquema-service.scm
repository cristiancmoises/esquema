(define-module (guix esquema-service)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (esquema runtime))

(define-record-type <esquema-config>
  (esquema-config name container)
  esquema-config?
  (name esquema-name)
  (container esquema-container))

(define (esquema-shepherd config)
  (list
   (shepherd-service
     (provision (list (string->symbol (esquema-name config))))
     (documentation "esquema container")
     (start
      #~(make-forkexec-constructor
         (list "guile" "-c"
           (string-append
            "(use-modules (esquema runtime))"
            "(run-container "
            (object->string '#$(esquema-container config))
            ")"))))
     (stop #~(make-kill-destructor))
     (respawn? #t))))

(define esquema-service-type
  (service-type
   (name 'esquema)
   (extensions
    (list
     (service-extension shepherd-root-service-type
                        esquema-shepherd)))
   (description "Guile-native container runtime")))

