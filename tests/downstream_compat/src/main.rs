use icann_rdap_common::check::CheckClass;
use strum::{EnumMessage, VariantArray};

#[derive(VariantArray, EnumMessage)]
enum Foo {
    Bar,
    Baz,
}

fn main() {
    let _ = Foo::Bar;
    let _ = Foo::Baz;

    for v in CheckClass::VARIANTS {
        println!("v = {v}");
    }

    println!("Downstream strum compatibility check passed!");
}
