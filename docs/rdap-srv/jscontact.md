# JSContact Support

The `rdap-srv-data` command provides support for generating RDAP entity objects with JSContact format. JSContact is a JSON-based format for contact information that serves as a modern alternative to vCard.

## Command Option

When creating RDAP entities using the `entity` subcommand, you can use the `--jscontact` flag to represent the entity with JSContact format instead of the traditional vCard format.

```bash
rdap-srv-data entity \
  --handle <HANDLE> \
  --base-url <BASE_URL> \
  --jscontact \
  [other entity options...]
```

## Usage Example

```bash
# Create an entity with JSContact format
rdap-srv-data entity \
  --handle "ABC123-EXAMPLE" \
  --base-url "https://rdap.example.com" \
  --full-name "John Doe" \
  --email "john.doe@example.com" \
  --voice "+1-555-123-4567" \
  --street "123 Main St" \
  --locality "Anytown" \
  --region "CA" \
  --country-name "United States" \
  --postal-code "12345" \
  --jscontact
```

## Server Configuration

The RDAP server can be configured to automatically convert vCard contacts to JSContact format using the `RDAP_SRV_JSCONTACT_CONVERSION` environment variable.

### Environment Variable

```bash
export RDAP_SRV_JSCONTACT_CONVERSION=<conversion_mode>
```

### Conversion Modes

The `RDAP_SRV_JSCONTACT_CONVERSION` variable accepts three values:

- **`none`** (default): Do not perform any JSContact conversions
- **`also`**: Convert vCard to JSContact and include both formats in the response
- **`only`**: Convert vCard to JSContact and remove the vCard format

### Configuration Examples

```bash
# Include both vCard and JSContact formats
export RDAP_SRV_JSCONTACT_CONVERSION=also

# Use only JSContact format (no vCard)
export RDAP_SRV_JSCONTACT_CONVERSION=only

# Disable JSContact conversion (default behavior)
export RDAP_SRV_JSCONTACT_CONVERSION=none
```
