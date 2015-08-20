#![feature(plugin)]
#![plugin(regex_macros)]
#![feature(path_ext)]

extern crate regex;
extern crate rustc_serialize;

use std::path::Path;
use std::env;
use rustc_serialize::json;
use std::io::prelude::*;
use std::fs::File;
use regex::Regex;
use std::fs::{read_dir, metadata};
use std::collections::BTreeMap;
use std::fmt;
use std::process;

fn to_regex_array(strings: &Vec<String>) -> Vec<Regex> {
	strings.iter().map(|string|{ 
		Regex::new(string.as_ref()).unwrap()
	}).collect()
}

fn matches_any(string: &str, exps: &Vec<Regex> ) -> bool {
	for r in exps {
		if r.is_match(string) {
			return true;
		}
	}
	return false;
}

struct Info<'a> {
    path: &'a String,
    line: usize,
    snippet: &'a str
}

#[derive(Debug)]
struct Warning {
	path: String,
	line: usize,
	snippet: String,
}

impl Warning {
	fn new(info: &Info) -> Self {
		Warning{
			path: info.path.clone(),
			line: info.line,
			snippet: info.snippet.to_owned()
		}
	}
}

impl fmt::Display for Warning {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "\t{}:{}\t\t{}", self.path, self.line, self.snippet)
	}
}

#[derive(Default)]
struct Warnings {
	map: BTreeMap<String, Vec<Warning>>
}

impl Warnings {
	fn add(&mut self, message: &String, info: &Info) {
		if !self.map.contains_key(message) {
			self.map.insert(message.clone(), vec![Warning::new(info)]);
		}
		else {
			self.map.get_mut(message).unwrap().push(Warning::new(info));
		}
	}
}

impl fmt::Display for Warnings {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		for (k, v) in &self.map {
			write!(f, "\n#### {}\n\n", k);	

			for warning in v {
				write!(f, "{}\n", warning);
			}
		}
		Ok(())
	}
}

#[derive(RustcDecodable, Debug)]
struct TestDesc {
	fail: Vec<String>,
	allow: Option<Vec<String>>,
	error: String,
	classOnly: Option<bool>,
	headerOnly: Option<bool>,
}

#[derive(RustcDecodable, Debug)]
struct ConfigDesc {
	roots: Vec<String>,
	excludes: Option<Vec<String>>,
	includes: Option<Vec<String>>,
	incremental: Option<bool>,
	tests: Vec<TestDesc>,
	safeTag: Option<String>
}

struct Test {
	fail: Vec<Regex>,
	allow: Vec<Regex>,
	error: String,
	class_only: bool,
	header_only: bool
}

impl Test {
	fn from_desc(desc: TestDesc) -> Self {
		Test {
			fail: to_regex_array(&desc.fail),
			allow: to_regex_array(&desc.allow.unwrap_or_default()),
			error: desc.error.clone(),
			class_only: desc.classOnly.unwrap_or(false),
			header_only: desc.headerOnly.unwrap_or(false)
		}
	}

	fn run(&self, line: &str, header: bool, class: bool) -> bool {
		if (self.class_only && !class) || (self.header_only && !header) {
			return false;
		}

		for fail in &self.fail {
			if fail.is_match(line) {
				for allow in &self.allow {
					if allow.is_match(line) {
						return false;
					}
				}
				return true;
			}
		}
		return false;
	}
}

struct Config {
	roots: Vec<String>,
	excludes: Vec<Regex>,
	includes: Vec<Regex>,
	incremental: bool,
	tests: Vec<Test>,
	safe_tag: String,

	class_regex: Regex
}

impl Config {
	fn from_desc(desc:ConfigDesc) -> Self {
		Config {
			roots: desc.roots,
			excludes: to_regex_array(&desc.excludes.unwrap_or_default()),
			includes: to_regex_array(&desc.includes.unwrap_or_default()),
			incremental: desc.incremental.unwrap_or(false),
			tests: desc.tests.into_iter().map(|td|{
				Test::from_desc(td)
			}).collect(),
			safe_tag: desc.safeTag.unwrap_or("/*SAFE_TAG*/".to_owned()),
			class_regex: regex!("(^|\\s)+class\\s+[^;]*$"),
		}
	}

	fn should_check(&self, path: &str) -> bool {
		matches_any(&path, &self.includes) && !matches_any(&path, &self.excludes)
	}
}

fn clean_cpp_file_content(file_content: &mut String) {
	assert!(file_content.len() > 0);

	enum State {
		Code,
		SkipLine,
		String,
		MultiLine,
	}

	let mut state = State::Code;
	unsafe { //because as_mut_vec ignores UTF8, lol
		let mut bytes = file_content.as_mut_vec();
		let mut cur = bytes[0] as char;
		for i in 1..bytes.len() {
			let next = bytes[i] as char;

			state = match state {
				State::Code if (cur == '/' && next == '/') || next == '#' 
					=> State::SkipLine,
				State::Code if cur == '"'
					=> State::String,
				State::Code if cur == '/' && next == '*' 
					=> State::MultiLine,
				State::Code
					=> State::Code,

				State::SkipLine if next == '\n' 
					=> State::Code,
				State::String if cur == '"' 
					=> State::Code,
				State::MultiLine if cur == '*' && next == '/' 
					=> State::Code,
				_ if next != '\n' => {
					bytes[i] = 'X' as u8; 
					state
				},
				_ => state
			};

			cur = next;
		}
 	}
}

fn walk(path: &str, paths: &mut Vec<String>) {
    for entry in read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if metadata(&entry.path()).unwrap().is_dir() {
            walk(&entry.path().to_str().unwrap(), paths);
        } else { 
        	paths.push( entry.path().as_path().to_str().unwrap().to_owned() ); 
        }
    }
}

fn examine(config: &Config, path: String, warnings: &mut Warnings){
	let mut file_content = String::new();

	let mut in_class = false;
	let in_header = path.ends_with(".h");
	let mut line_number = 0;

	{
		let mut file = File::open(&path).unwrap();	
		file.read_to_string(&mut file_content);
	}

	if file_content.len() <= 1 {
 		return;
	}
	
	//TODO ensure stuff is ASCII manually
	clean_cpp_file_content(&mut file_content);

	for line in file_content.split('\n') {
		line_number += 1;

		//TODO SAFE_TAG
		if !in_class && config.class_regex.is_match(line) {
			in_class = true; //TODO actually *exit* classes too...
		}

		//TODO //add a tab at the start to make pre-whitespaces coherent
		let info = Info{ 
			path: &path,
			line: line_number,
			snippet: line
		};

		for test in &config.tests {
			if test.run(line, in_header, in_class) {
				warnings.add(&test.error, &info);
			}
		}
	}
}

fn run(config: Config) -> usize {
	let mut paths:Vec<String> = vec![];
	let mut warnings = Warnings::default();

	for root in &config.roots {
		walk(root.as_ref(), &mut paths );
	}

	for path in paths {
		//TODO do all of them in a thread pool! (yes, disk too)
		//SSDs scale with the amount of reads
		if config.should_check(path.as_ref()) {
			examine(&config, path, &mut warnings);
		}
	}

	let count = warnings.map.iter().fold(0, |c, (_, v)| {c + v.len()});
	println!("{}", warnings);
	println!("Found {} issues!", count);

	count
}

fn main() {
	let args: Vec<String> = env::args().collect();
	if args.len() != 2 {
		println!("Pls provide the path to your JSON config.");
		println!("Usage: ./acpplinter path/to/your/config.json", );
		process::exit(0);
	}
	
	let path = Path::new(&args[1]);

	if !path.is_file() {
		println!("{} is not a file, or couldn't be found!", path.display());
		process::exit(1);
	}

	let rootpath = path.parent().unwrap();
	assert!(env::set_current_dir(rootpath).is_ok());

	if let Ok(mut file) = File::open(path) {
		let mut file_content = String::new();
		file.read_to_string(&mut file_content);

		match json::decode::<ConfigDesc>(file_content.as_ref()) {
			Ok(desc) => {
				if run(Config::from_desc(desc)) == 0 {
					process::exit(0);
				}
				else {
					process::exit(1);
				}
			},
			Err(e) => {
				println!("Invalid JSON");
				println!("{:?}", e);
			}
		}
	}
	else {
		println!("Cannot open config {}", path.display());
	}
}