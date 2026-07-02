;; manifest.scm — reproducible build & test environment for Esquema.
;;
;; Usage:
;;   guix shell -m manifest.scm -- make check
;;
;; Provides the C toolchain, libseccomp/libcap for the sandbox primitives,
;; Guile for the Scheme layer, and the auditing tools (cppcheck, valgrind)
;; used by the security/audit test targets.
(specifications->manifest
 (list "gcc-toolchain"
       "make"
       "pkg-config"
       "libseccomp"
       "libcap"
       "guile"
       "cppcheck"
       "valgrind"))
