extern crate regex;
extern crate rustc_serialize;
extern crate glob;

use std::env;
use rustc_serialize::json;
use std::io::prelude::*;
use std::fs::File;
use regex::Regex;
use std::fs::{read_dir, metadata};

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

struct Info {
    path: String,
    line: usize,
    snippet: String
}

#[derive(RustcDecodable, Debug)]
struct TestDesc {
	fail: Vec<String>,
	allow: Option<Vec<String>>,
	error: String,
	classOnly: Option<bool>,
	headerOnly: Option<bool>
}

#[derive(RustcDecodable, Debug)]
struct ConfigDesc {
	roots: Vec<String>,
	excludes: Option<Vec<String>>,
	includes: Option<Vec<String>>,
	incremental: Option<bool>,
	tests: Vec<TestDesc>
}

#[derive(Debug)]
struct Test {
	fail: Vec<Regex>,
	allow: Vec<Regex>,
	error: String,
	classOnly: bool,
	headerOnly: bool
}

impl Test {
	fn from_desc(desc: TestDesc) -> Self {
		Test {
			fail: to_regex_array(&desc.fail),
			allow: to_regex_array(&desc.allow.unwrap_or_default()),
			error: desc.error.clone(),
			classOnly: desc.classOnly.unwrap_or(false),
			headerOnly: desc.headerOnly.unwrap_or(false)
		}
	}

	fn run(&self, line: &str, isHeader: bool, isClass: bool, info: &Info) {

	}
}

#[derive(Debug)]
struct Config {
	roots: Vec<String>,
	excludes: Vec<Regex>,
	includes: Vec<Regex>,
	incremental: bool,
	tests: Vec<Test>
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
			}).collect()
		}
	}

	fn should_check(&self, path: &str) -> bool {
		matches_any(&path, &self.includes) && !matches_any(&path, &self.excludes)
	}
}

fn cleaned_file_content(path: String) -> String {

	enum State {
		Code,
		SkipLine,
		String,
		MultiLine,
	}

	let mut state = State::Code;

	let mut file = File::open(path).unwrap();		
	let mut file_content = String::new();

	file.read_to_string(&mut file_content);

	//TODO ensure stuff is ASCII manually
	unsafe {	
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

	file_content
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

fn run(config: Config) {
	let mut paths:Vec<String> = vec![];

	for root in &config.roots {
		walk(root.as_ref(), &mut paths );
	}

	//TODO this can be easily parallelized?
	for path in paths {
		if config.should_check(path.as_ref()) {
			println!("{}", cleaned_file_content(path));
		}
	}
}

fn main() {
	let path = "/Users/tommaso/DEV/Minecraftpe/mcpe-lint.json";

	let rootpath = "/Users/tommaso/DEV/Minecraftpe/";

	assert!(env::set_current_dir(rootpath).is_ok());

	if let Ok(mut file) = File::open(path) {
		let mut file_content = String::new();
		file.read_to_string(&mut file_content);

		match json::decode::<ConfigDesc>(file_content.as_ref()) {
			Ok(desc) => {
				run(Config::from_desc(desc))
			},
			Err(e) => {
				println!("Invalid JSON");
				println!("{:?}", e);
			}
		}
	}
	else {
		println!("Cannot open config {}", path);
	}
}