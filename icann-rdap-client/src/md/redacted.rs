use std::str::FromStr;

use icann_rdap_common::response::redacted::Redacted;
use jsonpath::replace_with;
use jsonpath_lib as jsonpath;
use jsonpath_rust::{JsonPathFinder, JsonPathInst};
use serde_json::{json, Value};

use super::{string::StringUtil, table::MultiPartTable, MdOptions, MdParams, ToMd};
use icann_rdap_common::response::RdapResponse;

/// The text to appear if something is redacted.
///
/// This should be REDACTED in bold.
pub const REDACTED_TEXT: &str = "*REDACTED*";

impl ToMd for &[Redacted] {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();

        // header
        let header_text = "Redacted".to_string();
        md.push_str(&header_text.to_header(params.heading_level, params.options));

        // multipart data
        let mut table = MultiPartTable::new();
        table = table.header_ref(&"Fields");

        for (index, redacted) in self.iter().enumerate() {
            let options = MdOptions {
                text_style_char: '*',
                ..Default::default()
            };

            // make the name bold
            let name = "Redaction";
            let b_name = name.to_bold(&options);
            // build the table
            table = table.and_data_ref(&b_name, &Some((index + 1).to_string()));

            // Get the data itself
            let name_data = redacted
                .name
                .description
                .clone()
                .or(redacted.name.type_field.clone());
            let method_data = redacted.method.as_ref().map(|m| m.to_string());
            let reason_data = redacted.reason.as_ref().map(|m| m.to_string());

            // Special case the 'column' fields
            table = table
                .and_data_ref(&"name".to_title_case(), &name_data)
                .and_data_ref(&"prePath".to_title_case(), &redacted.pre_path)
                .and_data_ref(&"postPath".to_title_case(), &redacted.post_path)
                .and_data_ref(
                    &"replacementPath".to_title_case(),
                    &redacted.replacement_path,
                )
                .and_data_ref(&"pathLang".to_title_case(), &redacted.path_lang)
                .and_data_ref(&"method".to_title_case(), &method_data)
                .and_data_ref(&"reason".to_title_case(), &reason_data);

            // we don't have these right now but if we put them in later we will need them
            // let check_params = CheckParams::from_md(params, typeid);
            // let mut checks = redacted.object_common.get_sub_checks(check_params);
            // checks.push(redacted.get_checks(check_params));
            // table = checks_to_table(checks, table, params);
        }

        // render table
        md.push_str(&table.to_md(params));
        md.push('\n');
        md
    }
}

// this is our public entry point
pub fn replace_redacted_items(orignal_response: RdapResponse) -> RdapResponse {
    // convert the RdapResponse to a string
    let rdap_json = serde_json::to_string(&orignal_response).unwrap();

    // Redaction is not a top-level entity so we have to check the JSON
    // to see if anything exists in the way of "redacted", this should find it in the rdapConformance
    if !rdap_json.contains("\"redacted\"") {
        // If there are no redactions, return the original response
        return orignal_response;
    }

    // convert the string to a JSON Value
    let mut rdap_json_response: Value = serde_json::from_str(&rdap_json).unwrap();

    // this double checks to see if "redacted" is an array
    if rdap_json_response["redacted"].as_array().is_none() {
        // If "redacted" is not an array, return the original response
        return orignal_response;
    }

    // Initialize the final response with the original response
    let mut response = orignal_response;
    // pull the redacted array out of the JSON
    let redacted_array_option = rdap_json_response["redacted"].as_array().cloned();

    // if there are any redactions we need to do some modifications
    if let Some(ref redacted_array) = redacted_array_option {
        let new_json_response = convert_redactions(&mut rdap_json_response, redacted_array).clone();
        // convert the Value back to a RdapResponse
        response = serde_json::from_value(new_json_response).unwrap();
    }

    // send the response back so we can display it to the client
    response
}

fn convert_redactions<'a>(
    rdap_json_response: &'a mut Value,
    redacted_array: &'a [Value],
) -> &'a mut Value {
    for item in redacted_array {
        let item_map = item.as_object().unwrap();
        let post_path = get_string_from_map(item_map, "postPath");
        let method = get_string_from_map(item_map, "method");

        // if method doesn't equal emptyValue or partialValue, we don't need to do anything, we can skip to the next item
        if method != "emptyValue" && method != "partialValue" && !post_path.is_empty() {
            continue;
        }

        match JsonPathInst::from_str(&post_path) {
            Ok(json_path) => {
                let finder =
                    JsonPathFinder::new(Box::new(rdap_json_response.clone()), Box::new(json_path));
                let matches = finder.find_as_path();
                if let Value::Array(paths) = matches {
                    if paths.is_empty() {
                        continue; // we don't need to do anything, we can skip to the next item
                    } else {
                        for path_value in paths {
                            if let Value::String(found_path) = path_value {
                                let no_value = Value::String("NO_VALUE".to_string());
                                let json_pointer = convert_to_json_pointer_path(&found_path);
                                let value_at_path = rdap_json_response
                                    .pointer(&json_pointer)
                                    .unwrap_or(&no_value);
                                if value_at_path.is_string() {
                                    // grab the value at the end point of the JSON path
                                    let end_of_path_value =
                                        match rdap_json_response.pointer(&json_pointer) {
                                            Some(value) => value.clone(),
                                            None => {
                                                continue;
                                            }
                                        };
                                    let replaced_json = replace_with(
                                        rdap_json_response.clone(),
                                        &found_path,
                                        &mut |x| {
                                            // STRING ONLY! This is the only spot where we are ACTUALLY replacing or updating something
                                            if x.is_string() {
                                                match x.as_str() {
                                                    Some("") => Some(json!("*REDACTED*")),
                                                    Some(s) => Some(json!(format!("*{}*", s))),
                                                    _ => Some(json!("*REDACTED*")),
                                                }
                                            } else {
                                                Some(end_of_path_value.clone()) // it isn't a string, put it back in there
                                            }
                                        },
                                    );
                                    match replaced_json {
                                        Ok(new_json) => *rdap_json_response = new_json,
                                        _ => {
                                            // why did we fail to modify the JSON?
                                        }
                                    };
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                // do nothing
            }
        }
    }

    rdap_json_response
}

// utility functions
fn convert_to_json_pointer_path(path: &str) -> String {
    let pointer_path = path
        .trim_start_matches('$')
        .replace('.', "/")
        .replace("['", "/")
        .replace("']", "")
        .replace('[', "/")
        .replace(']', "")
        .replace("//", "/");
    pointer_path
}

fn get_string_from_map(map: &serde_json::Map<String, Value>, key: &str) -> String {
    map.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use serde_json::Value;
    use std::error::Error;
    use std::fs::File;
    use std::io::Read;

    fn process_redacted_file(file_path: &str) -> Result<String, Box<dyn Error>> {
        let mut file = File::open(file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // this has to be setup very specifically, just like replace_redacted_items is setup.
        let mut rdap_json_response: Value = serde_json::from_str(&contents)?;
        let redacted_array_option = rdap_json_response["redacted"].as_array().cloned();
        // we are testing parse_redacted_json here -- just the JSON transforms
        if let Some(redacted_array) = redacted_array_option {
            crate::md::redacted::convert_redactions(&mut rdap_json_response, &redacted_array);
        } else {
            panic!("No redacted array found in the JSON");
        }
        let pretty_json = serde_json::to_string_pretty(&rdap_json_response)?;
        println!("{}", pretty_json);
        Ok(pretty_json)
    }

    #[test]
    fn test_process_empty_value() {
        let expected_output =
            std::fs::read_to_string("src/test_files/example-1_empty_value-expected.json").unwrap();
        let output = process_redacted_file("src/test_files/example-1_empty_value.json").unwrap();
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_process_partial_value() {
        let expected_output =
            std::fs::read_to_string("src/test_files/example-2_partial_value-expected.json")
                .unwrap();
        let output = process_redacted_file("src/test_files/example-2_partial_value.json").unwrap();
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_process_dont_replace_number() {
        let expected_output = std::fs::read_to_string(
            "src/test_files/example-3-dont_replace_redaction_of_a_number.json",
        )
        .unwrap();
        // we don't need an expected for this one, it should remain unchanged
        let output = process_redacted_file(
            "src/test_files/example-3-dont_replace_redaction_of_a_number.json",
        )
        .unwrap();
        assert_eq!(output, expected_output);
    }
}
