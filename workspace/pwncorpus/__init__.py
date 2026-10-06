"""pwncorpus - anonymous query & publication system for leaked-password fingerprints.

Pipeline:
  ingest (dedup + authz, hash-at-the-edge) -> build candidate publication
  (fixed-prefix buckets, min-set-size threshold) -> review -> atomic activate.

Only the *active* publication serves anonymous range queries. Retired
publications remain in the database and stay verifiable offline, but are
never served. Raw passwords are never stored: they are hashed (SHA-1) at
ingestion time and only fingerprints / counts persist.
"""

__version__ = "1.0.0"
