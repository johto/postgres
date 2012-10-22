-- Test database for pg_dump --format=split patch

BEGIN;

-- Create a basic schema to test basic functionality
CREATE SCHEMA basicschema;
SET search_path TO 'basicschema';

\i objects.sql

CREATE SCHEMA "tricky"" schema()";
SET search_path TO 'tricky" schema()';

\i objects.sql

-- tricky stuff in tricky schema
CREATE FUNCTION "tricky"" function()"("tricky"" type()", basicschema.footype)
	RETURNS basicschema.footype AS $$ SELECT 1; $$ LANGUAGE sql;

SET search_path TO public, pg_catalog;

-- extensions
CREATE EXTENSION pgcrypto WITH SCHEMA "tricky"" schema()";

-- dependency tests
CREATE SCHEMA dependency1;
CREATE SCHEMA dependency2;

CREATE TABLE dependency1.foo(a int PRIMARY KEY);
CREATE TABLE dependency2.bar(a int PRIMARY KEY REFERENCES dependency1.foo(a));

ALTER TABLE dependency1.foo ADD CONSTRAINT dep2_fkey FOREIGN KEY (a) REFERENCES dependency2.bar(a);

COMMIT;
