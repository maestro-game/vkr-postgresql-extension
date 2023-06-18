CREATE TYPE mmpt;

CREATE FUNCTION mmpt_in(cstring)
    RETURNS mmpt
    AS 'MODULE_PATHNAME'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION mmpt_out(mmpt)
    RETURNS cstring
    AS 'MODULE_PATHNAME'
    LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE mmpt (
   internallength = VARIABLE,
   input = mmpt_in,
   output = mmpt_out
);

CREATE FUNCTION create_mmpt(cstring, integer)
  RETURNS mmpt
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION insert_in_trie(mmpt, bytea, bytea, bytea)
  RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION find_in_trie(mmpt, bytea, bytea)
  RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION merkle_proof_key(mmpt, bytea, bytea)
  RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION validate_mmpt(mmpt, bytea)
  RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;
