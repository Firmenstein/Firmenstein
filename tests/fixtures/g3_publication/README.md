# Schema 17 rendering fixtures

These new fixtures retain the old g2 field examples for pure rendering and
contract-digest tests, with explicit schema 17 encoding. The g2 bytes remain
unchanged and must be rejected by the live schema. `publication: null` is an
unpublished checkpoint, never admissible to the production complete loader.
Real publication/consumption and tamper rejection use isolated tmp_path files
in `tests/test_generation_publication.py`.
