CREATE FUNCTION foof() RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql;
CREATE TABLE foot AS SELECT a FROM generate_series(1, 100) a;
CREATE TYPE footype AS (a int);

ALTER TABLE foot ALTER COLUMN a SET DEFAULT 0;

CREATE TABLE "tricky"" table()" ("tricky"" column()" int PRIMARY KEY);
CREATE TABLE "tricky"" table2()" (a int PRIMARY KEY REFERENCES "tricky"" table()" ("tricky"" column()"));
CREATE FUNCTION "tricky"" function()"() RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql;
CREATE TYPE "tricky"" type()" AS (a int);
CREATE FUNCTION "tricky"" function()"("tricky"" type()") RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql;

ALTER TABLE "tricky"" table()" ALTER COLUMN "tricky"" column()" SET DEFAULT "tricky"" function()"();

-- tricky dependencies
CREATE TABLE "tricky"" deptable()"(a int);
CREATE FUNCTION "tricky"" depfunction()"("tricky"" deptable()") RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql;
ALTER TABLE "tricky"" deptable()" ALTER COLUMN a SET DEFAULT "tricky"" depfunction()"(NULL);
ALTER TABLE "tricky"" deptable()" ADD CONSTRAINT acheck CHECK (a <> 747);
ALTER TABLE "tricky"" deptable()" ADD CONSTRAINT acheck2 CHECK (a > "tricky"" depfunction()"(NULL));

CREATE RULE "tricky"" rule()" AS ON INSERT TO "tricky"" deptable()" DO ALSO INSERT INTO "tricky"" table2()" VALUES (DEFAULT);

CREATE FUNCTION "tricky"" castfunction()"("tricky"" type()") RETURNS text AS $$ SELECT ($1).a::text; $$ LANGUAGE sql;
CREATE CAST ("tricky"" type()" AS TEXT) WITH FUNCTION "tricky"" castfunction()"("tricky"" type()") AS ASSIGNMENT;

CREATE OR REPLACE FUNCTION first_agg (anyelement, anyelement)
RETURNS anyelement LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT $1; $$;
 
CREATE AGGREGATE first (
        sfunc    = first_agg,
        basetype = anyelement,
        stype    = anyelement
);

CREATE AGGREGATE "tricky"" agg()" (
        sfunc    = first_agg,
        basetype = anyelement,
        stype    = anyelement
);

CREATE UNIQUE INDEX "tricky"" index()" ON "tricky"" table()"("tricky"" column()") WHERE "tricky"" column()" = 0;

ALTER TABLE "tricky"" table()" ADD CONSTRAINT "tricky"" exclusion()" EXCLUDE USING gist (box(point(0, 0), point("tricky"" column()", "tricky"" column()")) WITH &&); 

CREATE FUNCTION "tricky"" operator function()" (int, int) RETURNS bool AS $$ SELECT $1 = $2; $$ LANGUAGE sql;
CREATE OPERATOR =-*/<>=~!@#%^&|`? (PROCEDURE = "tricky"" operator function()", LEFTARG = int, RIGHTARG = int);

CREATE OPERATOR FAMILY "tricky"" operator family()" USING btree;
CREATE FUNCTION "tricky"" type()eq"("tricky"" type()", "tricky"" type()") RETURNS bool AS $$ SELECT $1 = $2; $$ LANGUAGE sql;
CREATE OPERATOR = (PROCEDURE = "tricky"" type()eq", LEFTARG = "tricky"" type()", RIGHTARG = "tricky"" type()");

CREATE OPERATOR CLASS "tricky"" operator class()" FOR TYPE "tricky"" type()"
USING btree FAMILY "tricky"" operator family()" AS
OPERATOR 1 = ("tricky"" type()", "tricky"" type()");

CREATE VIEW "tricky"" view()" AS SELECT * FROM "tricky"" table()";

CREATE SEQUENCE "tricky"" sequence()";

CREATE FUNCTION "tricky"" trigger function()"() RETURNS TRIGGER AS $$ BEGIN RETURN NULL; END $$ LANGUAGE plpgsql;

CREATE TRIGGER "tricky"" trigger()" BEFORE INSERT ON "tricky"" table()" FOR EACH STATEMENT EXECUTE PROCEDURE "tricky"" trigger function()"();
