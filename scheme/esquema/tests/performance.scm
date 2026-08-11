;;; performance.scm — startup latency, overhead vs raw exec, and a leak guard.
;;;
;;; Reports concrete numbers and applies only lenient bounds (so CI is not
;;; flaky) while still catching gross regressions and memory leaks.
(use-modules (srfi srfi-64)
             (srfi srfi-1)
             (srfi srfi-13)
             (ice-9 format)
             (ice-9 rdelim)
             (esquema container)
             (esquema sandbox)
             (esquema tests harness))

(define (now-ms)
  (/ (* 1000.0 (get-internal-real-time)) internal-time-units-per-second))

(define (time-thunk thunk)
  (let ((t0 (now-ms))) (thunk) (- (now-ms) t0)))

(define (percentile sorted p)
  (list-ref sorted (min (- (length sorted) 1)
                        (inexact->exact (floor (* p (length sorted)))))))

(define (bench label n thunk)
  (thunk)                                   ; warmup
  (let ((times (map (lambda (_) (time-thunk thunk)) (iota n))))
    (let* ((sorted (sort times <))
           (mean (/ (apply + times) n)))
      (format #t "  ~a: n=~a mean=~,2fms  min=~,2fms  p95=~,2fms  max=~,2fms~%"
              label n mean (first sorted) (percentile sorted 0.95) (last sorted))
      mean)))

;; Read this process's resident set size (kB) from /proc/self/status.
(define (self-rss-kb)
  (call-with-input-file "/proc/self/status"
    (lambda (port)
      (let loop ()
        (let ((line (read-line port)))
          (cond ((eof-object? line) 0)
                ((string-prefix? "VmRSS:" line)
                 (string->number (car (filter (lambda (s) (> (string-length s) 0))
                                              (cdr (string-split line #\space))))))
                (else (loop))))))))

(test-begin "esquema-performance")
(define runner (test-runner-current))
(define rootfs (make-test-rootfs))
(define shell (find-static-shell))

;; A minimal fully-isolated container that just exits 0.
(define (spawn-esquema)
  (with-sandbox
   (make-container "perf" rootfs (list "/bin/sh" "-c" "exit 0"))))

(define (spawn-esquema-nofile)
  (with-sandbox
   (make-container "perf-nofile" rootfs (list "/bin/sh" "-c" "exit 0")
                   #:limits (make-limits-v1 #f #f #f #f 32))))

;; Raw fork+exec of the same static shell, no isolation (baseline).
(define (spawn-raw)
  (let ((pid (primitive-fork)))
    (if (zero? pid)
        (begin (execl shell shell "-c" "exit 0") (primitive-exit 127))
        (waitpid pid))))

(format #t "~%Startup latency:~%")
(define raw-mean     (bench "raw fork+exec (no isolation)" 30 spawn-raw))
(define esq-mean     (bench "esquema full-isolation container" 30 spawn-esquema))
(define nofile-mean  (bench "esquema + RLIMIT_NOFILE readback" 30
                            spawn-esquema-nofile))
(define overhead     (- esq-mean raw-mean))
(format #t "  isolation overhead: ~,2fms per launch~%" overhead)
(format #t "  throughput: ~,1f containers/sec~%" (/ 1000.0 esq-mean))

;; P1: startup stays well under a generous ceiling (catches gross regressions).
(test-assert "P1 esquema startup mean < 500ms" (< esq-mean 500.0))
;; P2: overhead over raw exec is bounded.
(test-assert "P2 isolation overhead < 400ms" (< overhead 400.0))
(test-assert "P3 RLIMIT_NOFILE path remains below 2x Esquema baseline"
             (< nofile-mean (* 2.0 esq-mean)))

;; P4: no resident-memory growth across many launches (leak guard on the
;; config/FFI path).
(define rss-before (self-rss-kb))
(for-each (lambda (_) (spawn-esquema)) (iota 60))
(define rss-after (self-rss-kb))
(format #t "~%Leak guard: RSS ~akB -> ~akB (delta ~akB over 60 launches)~%"
        rss-before rss-after (- rss-after rss-before))
(test-assert "P4 launcher RSS growth < 8MB over 60 launches"
             (< (- rss-after rss-before) 8192))

(remove-rootfs rootfs)
(test-end "esquema-performance")
(exit (if (zero? (+ (test-runner-fail-count runner)
                    (test-runner-xpass-count runner))) 0 1))
