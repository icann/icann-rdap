CREATE TABLE entity (
    handle  TEXT PRIMARY KEY,
    content JSONB NOT NULL
);

CREATE TABLE domain (
    ldh_name     TEXT PRIMARY KEY,
    unicode_name TEXT,
    handle       TEXT,
    content      JSONB NOT NULL
);

CREATE TABLE nameserver (
    ldh_name     TEXT PRIMARY KEY,
    unicode_name TEXT,
    handle       TEXT,
    content      JSONB NOT NULL
);

CREATE TABLE autnum (
    start_autnum BIGINT PRIMARY KEY,
    end_autnum   BIGINT NOT NULL,
    handle       TEXT,
    content      JSONB NOT NULL
);

CREATE TABLE network (
    start_address INET PRIMARY KEY,
    end_address   INET NOT NULL,
    handle        TEXT,
    content       JSONB NOT NULL
);

CREATE TABLE srv_help (
    host    TEXT PRIMARY KEY,
    content JSONB NOT NULL
);
