CREATE TABLE entity (
    id      TEXT PRIMARY KEY, -- application generated
    handle  TEXT GENERATED ALWAYS AS (content->>'handle') STORED,
    content JSONB NOT NULL
);

CREATE TABLE domain (
    ldh_name     TEXT GENERATED ALWAYS AS (content->>'ldhName') STORED PRIMARY KEY,
    unicode_name TEXT GENERATED ALWAYS AS (content->>'unicodeName') STORED,
    handle       TEXT GENERATED ALWAYS AS (content->>'handle') STORED,
    content      JSONB NOT NULL
);

CREATE UNIQUE INDEX domain_ldh_name_lower_idx ON domain (LOWER(ldh_name));

CREATE TABLE nameserver (
    ldh_name     TEXT GENERATED ALWAYS AS (content->>'ldhName') STORED PRIMARY KEY,
    unicode_name TEXT GENERATED ALWAYS AS (content->>'unicodeName') STORED,
    handle       TEXT GENERATED ALWAYS AS (content->>'handle') STORED,
    content      JSONB NOT NULL
);

CREATE UNIQUE INDEX nameserver_ldh_name_lower_idx ON nameserver (LOWER(ldh_name));

CREATE TABLE autnum (
    start_autnum BIGINT GENERATED ALWAYS AS ((content->>'startAutnum')::bigint) STORED NOT NULL,
    end_autnum   BIGINT GENERATED ALWAYS AS ((content->>'endAutnum')::bigint) STORED NOT NULL,
    handle       TEXT GENERATED ALWAYS AS (content->>'handle') STORED,
    content      JSONB NOT NULL,
    PRIMARY KEY (start_autnum, end_autnum)
);

CREATE TABLE network (
    start_address INET GENERATED ALWAYS AS ((content->>'startAddress')::inet) STORED NOT NULL,
    end_address   INET GENERATED ALWAYS AS ((content->>'endAddress')::inet) STORED NOT NULL,
    handle        TEXT GENERATED ALWAYS AS (content->>'handle') STORED,
    content       JSONB NOT NULL,
    PRIMARY KEY (start_address, end_address)
);

CREATE TABLE srv_help (
    host    TEXT PRIMARY KEY,
    content JSONB NOT NULL
);
