# Formal evidence metadata

A repository containing formal TLA+ or Alloy sources must track formal/evidence.json. The document is a bounded, machine-readable description of the evidence context; it is not a proof.

It records an AWQ evidence class, a stable scope, positive integer bounds, assumptions, correspondence classification, explicit non-claims, and limitations. not-proven is the normal value: even a bounded model run does not prove the Python, filesystem, operating system, or implementation outside the stated abstraction. The checker rejects unknown fields, duplicate JSON keys, non-finite numbers, unbounded values, empty lists, and dynamic claims.

Validate the document with schemas/formal-evidence.schema.json and retain any native model runner as a separate project gate or future AWQ adapter.
