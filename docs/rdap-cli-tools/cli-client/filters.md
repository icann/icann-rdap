# Filters

When the `--filter` parameter is used, the output changes from the RDAP response to information filtered out of the RDAP response.
When no output type is explicitly specified with `--filter`, the output type is automatically set to CSV. Filters also work with
the JSON output formats.

The `--filter` parameter maybe specified multiple times, and/or the filters may be specified in one `--filter` parameter separate by a comma.

## Example

```bash
rdap --registrar --filter ldh-name,registrant-full-name,status icann.org >>my-domains.csv
```

## Filters

The available filters are:

* handle
* status
* object-class-name
* event
* rdap-conformance
* ldh-name
* unicode-name
* nameserver
* public-id
* ip-address
* role
* email
* full-name
* voice
* fax
* contact-uri
* country-name
* country-code
* start-autnum
* end-autnum
* start-ip-address
* end-ip-address
* ip-version
* cidr
* name
* type
* parent-handle
* registrant-email
* registrant-full-name
* registrant-voice
* registrant-fax
* registrant-contact-uri
* registrant-country-name
* registrant-country-code
* abuse-email
* abuse-full-name
* abuse-voice
* abuse-fax
* abuse-contact-uri
* abuse-country-name
* abuse-country-code
* technical-email
* technical-full-name
* technical-voice
* technical-fax
* technical-contact-uri
* technical-country-name
* technical-country-code
* registrar-email
* registrar-full-name
* registrar-voice
* registrar-fax
* registrar-contact-uri
* registrar-country-name
* registrar-country-code
