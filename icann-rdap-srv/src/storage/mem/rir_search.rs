use ipnet::Ipv4Net;
use prefix_trie::{AsView, PrefixMap};

pub fn get_rdap_down<T>(map: &PrefixMap<Ipv4Net, T>, query: &Ipv4Net) -> Vec<Ipv4Net> {
    let mut immediate_children = Vec::new();
    let mut current_cover: Option<Ipv4Net> = None;

    // view_at limits our iteration only to prefixes covered by the query
    let view = map.view_at(*query);

    for tree in view.iter() {
        if tree.prefix() == query {
            continue; // Skip the exact match of the query itself
        }

        if let Some(cover) = current_cover {
            if cover.contains(tree.prefix()) {
                // This node is a descendant of our current immediate child, skip it
                continue;
            }
        }

        // It is not covered by the previous immediate child, so it's a new one
        immediate_children.push(*tree.prefix());
        current_cover = Some(*tree.prefix());
    }

    immediate_children
}

pub fn get_rdap_bottom<T>(map: &PrefixMap<Ipv4Net, T>, query: &Ipv4Net) -> Vec<Ipv4Net> {
    let mut bottom_objects = Vec::new();
    let mut prev: Option<Ipv4Net> = None;

    let view = map.view_at(*query);

    for tree in view.iter() {
        if tree.prefix() == query {
            continue; // Skip the exact match
        }

        if let Some(p) = prev {
            // If the previous prefix does not cover the current one,
            // it has no children in the registry. It is a leaf!
            if !p.contains(tree.prefix()) {
                bottom_objects.push(p);
            }
        }
        prev = Some(*tree.prefix());
    }

    // The very last node in the traversal has no subsequent nodes to check,
    // meaning it is always a bottom object.
    if let Some(p) = prev {
        bottom_objects.push(p);
    }

    bottom_objects
}

#[cfg(test)]
mod tests {

    use ipnet::Ipv4Net;
    use prefix_trie::PrefixMap;

    #[test]
    fn test_get_spm_with_ordered_insertion() {
        // GIVEN
        let mut ip4_map: PrefixMap<Ipv4Net, String> = PrefixMap::new();
        ip4_map.insert("10.1.0.0/8".parse().unwrap(), "10.1.0.0/8".to_string());
        ip4_map.insert("10.1.0.0/16".parse().unwrap(), "10.1.0.0/16".to_string());
        ip4_map.insert("10.1.0.0/24".parse().unwrap(), "10.1.0.0/24".to_string());

        // WHEN
        let result = ip4_map.get_spm(&("10.1.0.1/32".parse().unwrap()));

        // THEN
        let (_net, value) = result.unwrap();
        assert_eq!(value, "10.1.0.0/8");
    }

    #[test]
    fn test_get_lpm_crawl_up() {
        // GIVEN
        let mut ip4_map: PrefixMap<Ipv4Net, String> = PrefixMap::new();
        ip4_map.insert("10.1.0.0/8".parse().unwrap(), "10.1.0.0/8".to_string());
        ip4_map.insert("10.1.0.0/16".parse().unwrap(), "10.1.0.0/16".to_string());
        ip4_map.insert("10.1.0.0/24".parse().unwrap(), "10.1.0.0/24".to_string());

        // WHEN
        let result = ip4_map.get_lpm(&("10.1.0.1/32".parse().unwrap()));

        // THEN
        let (net, value) = result.unwrap();
        assert_eq!(value, "10.1.0.0/24");

        // WHEN
        let result = ip4_map.get_lpm(&net.supernet().unwrap());

        // THEN
        let (net, value) = result.unwrap();
        assert_eq!(value, "10.1.0.0/16");

        // WHEN
        let result = ip4_map.get_lpm(&net.supernet().unwrap());

        // THEN
        let (_, value) = result.unwrap();
        assert_eq!(value, "10.1.0.0/8");
    }

    #[test]
    fn test_get_children() {
        // GIVEN
        let mut ip4_map: PrefixMap<Ipv4Net, String> = PrefixMap::new();
        ip4_map.insert("10.0.0.0/8".parse().unwrap(), "10.0.0.0/8".to_string());
        ip4_map.insert("10.1.0.0/8".parse().unwrap(), "10.1.0.0/8".to_string());
        ip4_map.insert("10.1.0.0/12".parse().unwrap(), "10.1.0.0/12".to_string());
        ip4_map.insert("10.1.0.0/16".parse().unwrap(), "10.1.0.0/16".to_string());
        ip4_map.insert("10.2.0.0/16".parse().unwrap(), "10.2.0.0/16".to_string());
        ip4_map.insert("10.1.0.0/24".parse().unwrap(), "10.1.0.0/24".to_string());

        // WHEN
        let parent: Ipv4Net = "10.1.0.1/8".parse().unwrap();
        let children = ip4_map
            .children(&parent)
            .filter(|(p, _)| p.prefix_len() > parent.prefix_len())
            .collect::<Vec<_>>();

        // THEN
        children.iter().for_each(|n| {
            dbg!(n);
        });
        assert_eq!(children.len(), 4);
    }
}
