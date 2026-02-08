(define-module (esquema container)
  #:use-module (srfi srfi-9)
  #:export (container
            container?
            container-name
            container-rootfs
            container-command))

;; Container record
(define-record-type <container>
  (container name rootfs command)
  container?
  (name    container-name)
  (rootfs  container-rootfs)
  (command container-command))
