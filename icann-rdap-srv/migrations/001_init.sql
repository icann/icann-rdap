-- trgm trusted extension comes with pg

CREATE EXTENSION IF NOT EXISTS pg_trgm;


------------------------
-- last public DB update
------------------------
 
CREATE TABLE last_rdap_update (
    id INT PRIMARY KEY CHECK (id = 1),
    last_db_update TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION notify_db_update()
RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify(
    'rdap_db_update', 
    to_char(NEW.last_db_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER rdap_db_update_trigger
AFTER INSERT OR UPDATE ON last_rdap_update
FOR EACH ROW
EXECUTE FUNCTION notify_db_update();

----------------
-- entity (rdap)
----------------

CREATE TABLE entity (
    handle  TEXT PRIMARY KEY,
    fn      TEXT,
    content JSONB NOT NULL
);

-- ILIKE wildcard search on handle (search_entities_by_handle) cannot use a B-tree, so it needs
-- a trigram GIN index to avoid seq-scanning the whole table.
CREATE INDEX entity_handle_trgm_idx ON entity USING GIN (handle gin_trgm_ops);

-- Same for full-name search (search_entities_by_full_name): ILIKE on fn also needs a trigram index.
CREATE INDEX entity_fn_trgm_idx ON entity USING GIN (fn gin_trgm_ops);

CREATE OR REPLACE FUNCTION set_entity_pk_from_json()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.handle IS NULL THEN
        NEW.handle := NEW.content->>'handle';
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_set_entity_pk_from_json
BEFORE INSERT ON entity
FOR EACH ROW
EXECUTE FUNCTION set_entity_pk_from_json();

---------
-- domain
---------

-- Helper function to get nameserver v4s to inet[]
CREATE OR REPLACE FUNCTION extract_nested_v4_ips(data jsonb)
RETURNS inet[] LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT COALESCE(
    ARRAY(
      SELECT ((jsonb_path_query(data, '$.nameservers[*].ipAddresses.v4[*]')) #>> '{}')::inet
    ),
    '{}'::inet[]
  );
$$;

-- Helper function to get nameserver v6s to inet[]
CREATE OR REPLACE FUNCTION extract_nested_v6_ips(data jsonb)
RETURNS inet[] LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT COALESCE(
    ARRAY(
      SELECT ((jsonb_path_query(data, '$.nameservers[*].ipAddresses.v6[*]')) #>> '{}')::inet
    ),
    '{}'::inet[]
  );
$$;

-- Helper function to get nameserver ldhNames to text[]
CREATE OR REPLACE FUNCTION extract_nested_ns_ldh_names(data jsonb)
RETURNS text[] LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT COALESCE(
    ARRAY(
      SELECT ((jsonb_path_query(data, '$.nameservers[*].ldhName')) #>> '{}')::text
    ),
    '{}'::text[]
  );
$$;

CREATE TABLE domain (
    ldh_name          TEXT PRIMARY KEY,
    unicode_name      TEXT GENERATED ALWAYS AS (content->>'unicodeName') STORED,
    handle            TEXT GENERATED ALWAYS AS (content->>'handle') STORED,
    ns_v4             INET[] GENERATED ALWAYS AS (extract_nested_v4_ips(content)) STORED,
    ns_v6             INET[] GENERATED ALWAYS AS (extract_nested_v6_ips(content)) STORED,
    ns_ldh_name       TEXT[] GENERATED ALWAYS AS (extract_nested_ns_ldh_names(content)) STORED,
    net_start_address INET GENERATED ALWAYS as ((content->'network'->>'startAddress')::inet) STORED,
    net_end_address   INET GENERATED ALWAYS as ((content->'network'->>'endAddress')::inet) STORED,
    content           JSONB NOT NULL
);

CREATE UNIQUE INDEX domain_ldh_name_lower_idx ON domain (LOWER(ldh_name));

CREATE INDEX domain_unicode_name_idx ON domain(unicode_name);

CREATE INDEX domain_handle_idx ON domain(handle);

CREATE INDEX domain_ns_v4_idx on domain USING GIN(ns_v4);

CREATE INDEX domain_ns_v6_idx on domain USING GIN(ns_v6);

CREATE INDEX domain_net_start_address_idx on domain(net_start_address);

CREATE INDEX domain_net_end_address_idx on domain(net_end_address);

-- Indexed support for wildcard/regex search over a domain's nameserver LDH names.
-- `domain.ns_ldh_name` is a TEXT[] generated column; element-level pattern matching on it
-- cannot be indexed (the default GIN array opclass only serves exact-element operators, and
-- pg_trgm refuses to build on text[]). So we denormalize the names into a scalar column that
-- CAN carry a trigram GIN index, kept in sync with `domain.content` via a trigger. The search
-- then filters through this indexed junction table instead of seq-scanning the domain table.
CREATE TABLE domain_ns (
    domain_ldh_name TEXT NOT NULL REFERENCES domain (ldh_name) ON DELETE CASCADE,
    ns_name         TEXT NOT NULL
);

CREATE INDEX domain_ns_name_trgm_idx ON domain_ns USING GIN (ns_name gin_trgm_ops);

-- Keep domain_ns in sync with the generated column. The names are derived solely from
-- `content`, so re-syncing whenever content changes is complete. Domain deletion is handled
-- by the FK's ON DELETE CASCADE above.
CREATE OR REPLACE FUNCTION fn_sync_domain_ns() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM domain_ns WHERE domain_ldh_name = NEW.ldh_name;
    INSERT INTO domain_ns (domain_ldh_name, ns_name)
    SELECT NEW.ldh_name, unnest(NEW.ns_ldh_name);
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_sync_domain_ns
AFTER INSERT OR UPDATE OF content ON domain
FOR EACH ROW EXECUTE FUNCTION fn_sync_domain_ns();

CREATE OR REPLACE FUNCTION set_domain_pk_from_json()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.ldh_name IS NULL THEN
        NEW.ldh_name := NEW.content->>'ldhName';
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_set_domain_pk_from_json
BEFORE INSERT ON domain
FOR EACH ROW
EXECUTE FUNCTION set_domain_pk_from_json();

-------------
-- nameserver
-------------

-- Helper function to convert a JSON array of IP strings to inet[]
CREATE OR REPLACE FUNCTION jsonb_to_inet_array(arr jsonb)
RETURNS inet[] LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE 
    WHEN jsonb_typeof(arr) = 'array' 
    THEN ARRAY(SELECT elem::inet FROM jsonb_array_elements_text(arr) AS elem)
    ELSE NULL
  END;
$$;

CREATE TABLE nameserver (
    ldh_name     TEXT PRIMARY KEY,
    unicode_name TEXT GENERATED ALWAYS AS (content->>'unicodeName') STORED,
    handle       TEXT GENERATED ALWAYS AS (content->>'handle') STORED,
    v4           INET[] GENERATED ALWAYS AS (jsonb_to_inet_array(content::jsonb -> 'ipAddresses' -> 'v4')) STORED,
    v6           INET[] GENERATED ALWAYS AS (jsonb_to_inet_array(content::jsonb -> 'ipAddresses' -> 'v6')) STORED,
    content      JSONB NOT NULL
);

CREATE UNIQUE INDEX nameserver_ldh_name_lower_idx ON nameserver (LOWER(ldh_name));

CREATE INDEX nameserver_ldh_name_trgm ON nameserver USING GIN(ldh_name gin_trgm_ops);

CREATE INDEX nameserver_unicode_name_idx ON nameserver(unicode_name);

CREATE INDEX nameserver_handle_idx ON nameserver(handle);

CREATE INDEX nameserver_v4 ON nameserver USING GIN(v4);

CREATE INDEX nameserver_v6 on nameserver USING GIN(v6);

CREATE OR REPLACE FUNCTION set_nameserver_pk_from_json()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.ldh_name IS NULL THEN
        NEW.ldh_name := NEW.content->>'ldhName';
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_set_nameserver_pk_from_json
BEFORE INSERT ON nameserver
FOR EACH ROW
EXECUTE FUNCTION set_nameserver_pk_from_json();

---------
-- autnum
---------

CREATE TABLE autnum (
    start_autnum BIGINT NOT NULL,
    end_autnum   BIGINT NOT NULL,
    handle       TEXT GENERATED ALWAYS AS (content->>'handle') STORED,
    name         TEXT GENERATED ALWAYS AS (content->>'name') STORED,
    content      JSONB NOT NULL,
    PRIMARY KEY (start_autnum, end_autnum)
);

CREATE INDEX autnum_handle_idx ON autnum(handle);

CREATE INDEX autnum_name_idx ON autnum(name);

CREATE OR REPLACE FUNCTION set_autnum_pk_from_json()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.start_autnum IS NULL THEN
        NEW.start_autnum := (NEW.content->>'startAutnum')::bigint;
    END IF;
    IF NEW.end_autnum IS NULL THEN
        NEW.end_autnum := (NEW.content->>'endAutnum')::bigint;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_set_autnum_pk_from_json
BEFORE INSERT ON autnum
FOR EACH ROW
EXECUTE FUNCTION set_autnum_pk_from_json();

----------
-- network
----------

CREATE TABLE network (
    start_address INET NOT NULL,
    end_address   INET NOT NULL,
    handle        TEXT GENERATED ALWAYS AS (content->>'handle') STORED,
    name          TEXT GENERATED ALWAYS AS (content->>'name') STORED,
    content       JSONB NOT NULL,
    PRIMARY KEY (start_address, end_address)
);

CREATE INDEX network_handle_idx ON network(handle);

CREATE INDEX network_name_idx ON network(name);

CREATE OR REPLACE FUNCTION set_network_pk_from_json()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.start_address IS NULL THEN
        NEW.start_address := (NEW.content->>'startAddress')::inet;
    END IF;
    IF NEW.end_address IS NULL THEN
        NEW.end_address := (NEW.content->>'endAddress')::inet;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_set_network_pk_from_json
BEFORE INSERT ON network
FOR EACH ROW
EXECUTE FUNCTION set_network_pk_from_json();

------
-- srv
------

CREATE TABLE srv_help (
    host    TEXT PRIMARY KEY,
    content JSONB NOT NULL
);
