#![feature(plugin)]
#![plugin(regex_macros)]

extern crate regex;
extern crate rustc_serialize;
extern crate time;

use time::precise_time_ns;
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

struct Info<'a> {
    path: &'a String,
    line: usize,
    snippet: &'a str
}

#[derive(Debug)]
struct Warning {
	message: String,
	path: String,
	line: usize,
	snippet: String,
}

impl Warning {
	fn new(message: &String, info: &Info) -> Self {
		Warning{
			message: message.clone(), //TODO don't copy string?
			path: info.path.clone(),
			line: info.line,
			snippet: info.snippet.to_owned()
		}
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

	fn run(&self, line: &str, header: bool, class: bool, info: &Info) -> Option<Warning> {
		if (self.class_only && !class) || (self.header_only && !header) {
			return None;
		}

		for fail in &self.fail {
			if fail.is_match(line) {
				for allow in &self.allow {
					if allow.is_match(line) {
						return None
					}
				}

				return Some(Warning::new( &self.error, info))
			}
		}
		return None;
	}
}

struct Config {
	roots: Vec<String>,
	excludes: Vec<Regex>,
	includes: Vec<Regex>,
	incremental: bool,
	tests: Vec<Test>,
	safe_tag: String,
	
	class_regex: Regex,
	warnings: Vec<Warning>
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
			class_regex: regex!("\\s+class\\s+[^;]*$"),
			warnings: vec![]
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

fn examine(config: &Config, path: String, warnings: &mut Vec<Warning>){
	//println!("Checking {}", path);
	
	let mut file_content = String::new();

	let mut in_class = false;
	let in_header = path.ends_with(".h");
	let mut line_number = 0;

	{
		let mut file = File::open(&path).unwrap();	
		file.read_to_string(&mut file_content);
	}

	//TODO ensure stuff is ASCII manually
	if file_content.len() <= 1 {
 		println!("{} is empty", path);
 		return;
	}
	
	clean_cpp_file_content(&mut file_content);

	for line in file_content.split('\n') {
		line_number += 1;

		//TODO SAFE_TAG

		let start = time::precise_time_ns();
		if config.class_regex.is_match(line) {
			in_class = true; //TODO actually *exit* classes too...
		}
		let elapsed = time::precise_time_ns() - start;

		if line_number % 100 == 0 {
			println!("{:?}", elapsed);
		}

		// //TODO //add a tab at the start to make pre-whitespaces coherent
		// let info = Info{ 
		// 	path: &path,
		// 	line: line_number,
		// 	snippet: line
		// };

		// for test in &config.tests {
		// 	if let Some(warning) = test.run(line, in_header, in_class, &info) {
		// 		warnings.push(warning);
		// 	}
		// }
	}
}

fn run(config: Config) {
	let mut paths:Vec<String> = vec![];
	let mut warnings: Vec<Warning> = vec!();

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

	println!("{:?}", warnings);
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