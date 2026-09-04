-- entity (rdap)

CREATE TABLE entity (
    handle  TEXT PRIMARY KEY,
    fn      TEXT,
    content JSONB NOT NULL
);

CREATE INDEX entity_fn_idx ON entity(fn);

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

-- domain

CREATE TABLE domain (
    ldh_name     TEXT PRIMARY KEY,
    unicode_name TEXT GENERATED ALWAYS AS (content->>'unicodeName') STORED,
    handle       TEXT GENERATED ALWAYS AS (content->>'handle') STORED,
    content      JSONB NOT NULL
);

CREATE UNIQUE INDEX domain_ldh_name_lower_idx ON domain (LOWER(ldh_name));

CREATE INDEX domain_unicode_name_idx ON domain(unicode_name);

CREATE INDEX domain_handle_idx ON domain(handle);

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

-- nameserver

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

CREATE INDEX nameserver_unicode_name_idx ON nameserver(unicode_name);

CREATE INDEX nameserver_handle_idx ON nameserver(handle);

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

-- autnum

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

-- network

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

-- srv

CREATE TABLE srv_help (
    host    TEXT PRIMARY KEY,
    content JSONB NOT NULL
);
