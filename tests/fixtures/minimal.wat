;; Minimal WAT fixture used to verify that the loader accepts WebAssembly Text
;; format and assembles it to binary before analysis. This module has no
;; contractspecv0 section, so the downstream parser will report "no spec found"
;; rather than any comparison findings — which is the correct, expected outcome.
(module)
