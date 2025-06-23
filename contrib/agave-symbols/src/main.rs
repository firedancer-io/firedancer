use clap::{Arg, ArgAction, ArgMatches, Command};
use goblin::{Object, elf::Elf};
use lazy_static::lazy_static;
use regex::Regex;
use rustc_demangle::demangle;

lazy_static! {
    static ref MATCH_HEX_SUFFIX: Regex = Regex::new(r"::h[0-9a-fA-F]+$").unwrap();
}

fn process_name(mut name: String, with_std: bool) {
    if !name.contains("serde::de::Deserialize") {
        return;
    }
    if name.contains("::__Visitor") || name.contains("::__FieldVisitor") {
        return;
    }
    if name.contains("bincode::") || name.contains("serde_json::") || name.contains("serde_yaml::") {
        return;
    }
    if name.contains("serde::__private") {
        return;
    }
    if MATCH_HEX_SUFFIX.is_match(&name) {
        name = name[..name.len()-19].to_string();
    }
    if !with_std {
        if name.contains(" for alloc::") || name.contains(" for std::") || name.contains(" for core::") {
            return;
        }
    }
    if name.contains("serde::de::Deserializer::__deserialize_content") {
        return;
    }
    if name.contains("::deserialize::PrimitiveVisitor") {
        return;
    }
    println!("{}", name);
}

fn process_object(object: &Elf<'_>, with_std: bool) {
    let symtab = &object.syms;
    let strtab = &object.strtab;
    for sym in symtab.into_iter() {
        let mangled_option = strtab.get_at(sym.st_name as usize);
        let mangled = if let Some(name) = mangled_option {
            name.to_string()
        } else {
            continue;
        };
        process_name(demangle(&mangled).to_string(), with_std);
    }
}

fn cmd_serde(matches: &ArgMatches) {
    let with_std = *matches.get_one::<bool>("with-std").unwrap();
    let object_bytes = std::fs::read(
        matches
            .get_one::<String>("binary")
            .expect("binary argument is required"),
    )
    .expect("Failed to read binary file");
    let object = Object::parse(&object_bytes).expect("Failed to parse binary file");
    match object {
        Object::Elf(elf) => process_object(&elf, with_std),
        Object::Archive(archive) => {
            for i in 0..archive.len() {
                if let Some(entry) = archive.get_at(i) {
                    let offset = entry.offset as usize;
                    let size = entry.size() as usize;
                    let slice = &object_bytes[offset..offset + size];
                    if let Ok(elf) = Elf::parse(slice) {
                        process_object(&elf, with_std);
                    }
                }
            }
        }
        _ => panic!("Unsupported object format"),
    }
}

fn main() {
    let matches = Command::new("agave-symbols")
        .about("Analyze debug symbols of an Agave build")
        .subcommand_required(true)
        .subcommand(
            Command::new("serde")
                .about("Find custom serde Deserialize implementations")
                .arg(
                    Arg::new("binary")
                        .required(true)
                        .help("Path to binary including Agave code"),
                )
                .arg(
                    Arg::new("with-std")
                        .long("with-std")
                        .help("Include symbols from the standard library")
                        .required(false)
                        .action(ArgAction::SetTrue),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("serde", sub_matches)) => cmd_serde(sub_matches),
        _ => unreachable!(),
    }
}
