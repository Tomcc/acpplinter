extern crate clap;
extern crate num_cpus;
extern crate regex;
extern crate rustc_serialize;
extern crate threadpool;

use clap::{App, Arg};
use regex::Regex;
use rustc_serialize::json;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::File;
use std::fs::{metadata, read_dir};
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::mpsc;
use threadpool::ThreadPool;

fn to_absolute_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    let canonical = try!(std::fs::canonicalize(path));
    if canonical.is_absolute() {
        return Ok(canonical);
    }

    let mut root = try!(std::env::current_dir());
    root.push(&canonical);
    Ok(root)
}

fn to_regex_array(strings: &Vec<String>) -> Vec<Regex> {
    strings
        .iter()
        .map(|string| Regex::new(string.as_ref()).unwrap())
        .collect()
}

fn to_unix_string(path: &Path) -> Cow<str> {
    let mut string = path.to_string_lossy();

    if let Some(_) = string.as_ref().find('\\') {
        string = Cow::Owned(string.as_ref().replace("\\", "/"));
    }

    return string;
}

fn matches_any(path: &Path, exps: &Vec<Regex>) -> bool {
    for r in exps {
        if r.is_match(&to_unix_string(path)) {
            return true;
        }
    }
    return false;
}

struct Info<'a> {
    path: PathBuf,
    line: Option<usize>,
    snippet: Option<&'a str>,
}

#[derive(Debug)]
struct Warning {
    path: PathBuf,
    line: Option<usize>,
    snippet: Option<String>,
    blame: Option<String>,
}

impl Warning {
    fn new(info: &Info) -> Self {
        Warning {
            path: info.path.clone(),
            line: info.line,
            blame: None,
            snippet: match info.snippet {
                Some(snippet) => Some(snippet.to_owned()),
                None => None,
            },
        }
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\t")?;

        if let Some(ref blame) = self.blame {
            write!(f, "{}\t\t{}", blame, self.snippet.as_ref().unwrap()) //snippet must exist if there is a blame
        } else {
            if let Some(ref line) = self.line {
                write!(
                    f,
                    "{}:{}\t\t{}",
                    self.path.display(),
                    line,
                    self.snippet.as_ref().unwrap() //snippet must exist if there is a line
                )
            } else {
                write!(f, "{}", self.path.display())
            }
        }
    }
}

#[derive(Default)]
struct Warnings {
    map: BTreeMap<String, Vec<Warning>>,
}

impl Warnings {
    fn add(&mut self, message: &str, info: &Info) {
        if !self.map.contains_key(message) {
            self.map
                .insert(message.to_owned(), vec![Warning::new(info)]);
        } else {
            self.map.get_mut(message).unwrap().push(Warning::new(info));
        }
    }

    fn add_map(&mut self, other: Warnings) {
        for (k, v) in other.map {
            if let Some(mut vec) = self.map.get_mut(&k) {
                for elem in v {
                    //println!("{}", elem);
                    vec.push(elem);
                }
                return;
            }

            self.map.insert(k.clone(), v);
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

impl fmt::Display for Warnings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (k, v) in &self.map {
            write!(f, "\n#### {}\n\n", k).unwrap();

            for warning in v {
                write!(f, "{}\n", warning).unwrap();
            }
        }
        Ok(())
    }
}

#[derive(RustcDecodable, Debug, Clone, Default)]
struct ExpectedFailsDesc {
    exactly: u32,
    //TODO greater than and less than?
}

#[derive(RustcDecodable, Debug)]
#[allow(non_snake_case)]
struct TestDesc {
    fail: Vec<String>,
    allow: Option<Vec<String>>,
    error: String,
    classOnly: Option<bool>,
    headerOnly: Option<bool>,
    include_paths: Option<Vec<String>>,
    exclude_paths: Option<Vec<String>>,
    expected_fails: Option<ExpectedFailsDesc>,
}

#[derive(RustcDecodable, Debug)]
#[allow(non_snake_case)]
struct ConfigDesc {
    roots: Vec<String>,
    excludes: Option<Vec<String>>,
    includes: Option<Vec<String>>,
    removeStrings: Option<bool>,
    removeComments: Option<bool>,
    tests: Vec<TestDesc>,
    safeTag: Option<String>,
}

#[derive(Clone)]
struct Test {
    fail: Vec<Regex>,
    allow: Vec<Regex>,
    error: String,
    class_only: bool,
    header_only: bool,
    include_paths: Vec<Regex>,
    exclude_paths: Vec<Regex>,
    expected_fails: ExpectedFailsDesc,
}

impl Test {
    fn from_desc(desc: TestDesc) -> Self {
        Test {
            fail: to_regex_array(&desc.fail),
            allow: to_regex_array(&desc.allow.unwrap_or_default()),
            error: desc.error.clone(),
            class_only: desc.classOnly.unwrap_or(false),
            header_only: desc.headerOnly.unwrap_or(false),
            include_paths: to_regex_array(&desc.include_paths.unwrap_or_default()),
            exclude_paths: to_regex_array(&desc.exclude_paths.unwrap_or_default()),
            expected_fails: desc.expected_fails.unwrap_or_default(),
        }
    }

    fn runs_on_path(&self, path: &Path) -> bool {
        if self.include_paths.len() > 0 && !matches_any(path, &self.include_paths) {
            return false;
        }

        if self.exclude_paths.len() > 0 && matches_any(path, &self.exclude_paths) {
            return false;
        }
        return true;
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

#[derive(Clone)]
struct Config {
    roots: Vec<String>,
    excludes: Vec<Regex>,
    includes: Vec<Regex>,
    remove_strings: bool,
    remove_comments: bool,
    tests: Vec<Test>,
    safe_tag_regex: Regex,

    class_regex: Regex,
}

impl Config {
    fn from_desc(desc: ConfigDesc) -> Self {
        Config {
            roots: desc.roots,
            excludes: to_regex_array(&desc.excludes.unwrap_or_default()),
            includes: to_regex_array(&desc.includes.unwrap_or_default()),
            remove_strings: desc.removeStrings.unwrap_or(true),
            remove_comments: desc.removeComments.unwrap_or(true),
            tests: desc.tests
                .into_iter()
                .map(|td| Test::from_desc(td))
                .collect(),
            safe_tag_regex: Regex::new(".*/\\*safe\\*/.*").unwrap(),
            class_regex: Regex::new("(^|\\s)+class\\s+[^;]*$").unwrap(),
        }
    }

    fn should_check(&self, path: &Path) -> bool {
        matches_any(&path, &self.includes) && !matches_any(&path, &self.excludes)
    }
}

fn clean_cpp_file_content(config: &Config, file_content: &mut String, ignore_safe: bool) {
    assert!(file_content.len() > 0);

    //remove all lines containing a safe tag
    if !ignore_safe {
        if let Cow::Owned(modified) = config.safe_tag_regex.replace_all(&file_content, "") {
            *file_content = modified.to_owned();
        }
    }

    enum State {
        Code,
        SkipLine,
        Preprocessor,
        String,
        Char,
        MultiLine,
    }

    let mut state = State::Code;
    unsafe {
        // because as_mut_vec ignores UTF8, lol
        let bytes = file_content.as_bytes_mut();
        let mut i = 0;
        while i < bytes.len() - 1 {
            let cur = bytes[i] as char;
            let next = bytes[i + 1] as char;

            state = match state {
                State::Code if config.remove_comments && cur == '/' && next == '/' => {
                    State::SkipLine
                }
                State::Code if config.remove_strings && cur == '"' => State::String,
                State::Code if config.remove_strings && cur == '\'' => State::Char,
                State::Code if config.remove_comments && cur == '/' && next == '*' => {
                    State::MultiLine
                }
                State::Code if cur == '#' => State::Preprocessor,

                //Preprocessor state: remain in the state until \n is found
                State::Preprocessor if next == '\n' => State::Code,
                State::Preprocessor => State::Preprocessor,

                //unknown character: remain in Code state
                State::Code => State::Code,

                //after this line, all iterations on one of these states cause X to be written in replacement
                State::SkipLine if next == '\n' => State::Code,
                State::String if cur == '\\' => {
                    //escape char, skip next
                    bytes[i] = 'X' as u8;
                    i += 1;
                    bytes[i] = 'X' as u8;
                    State::String
                }
                State::String if cur == '"' => State::Code,
                State::Char if cur == '\'' => State::Code,
                State::MultiLine if cur == '*' && next == '/' => State::Code,
                _ => {
                    bytes[i] = 'X' as u8;
                    state
                }
            };
            i += 1;
        }
    }
}

fn walk(path: &Path, paths: &mut Vec<PathBuf>) {
    if let Ok(dir_entries) = read_dir(path) {
        for entry in dir_entries {
            let entry = entry.unwrap();
            if metadata(&entry.path()).unwrap().is_dir() {
                walk(&entry.path(), paths);
            } else {
                paths.push(entry.path().to_path_buf());
            }
        }
    } else if metadata(path).unwrap().is_file() {
        paths.push(path.to_path_buf());
    } else {
        println!("Cannot find folder {:?}", path);
    }
}

fn examine(
    config: &Config,
    path: &Path,
    replace_original_with_preprocessed: bool,
    ignore_safe: bool,
) -> Warnings {
    let mut warnings = Warnings::default();

    let mut file_content = String::new();

    let mut in_class = false;
    let in_header = path.ends_with(".h");
    let mut line_number = 0;

    let mut file = File::open(&path).unwrap();
    let result = file.read_to_string(&mut file_content);

    if result.is_err() {
        warnings.add(
            "This file contains invalid UTF8",
            &Info {
                path: path.to_path_buf(),
                line: None,
                snippet: None,
            },
        );
        return warnings;
    }

    if file_content.len() <= 1 {
        return warnings;
    }

    // TODO ensure stuff is ASCII manually
    clean_cpp_file_content(config, &mut file_content, ignore_safe);

    if replace_original_with_preprocessed {
        // debug option: print out whatever this file looks like after cleaning
        // let out_path = append_to_extension(path.to_owned(), ".preproc");
        let out_path = path;

        println!("{:?}", out_path);
        let mut outfile = File::create(out_path).unwrap();
        outfile.write(file_content.as_bytes()).unwrap();
    }

    let mut test_batch = vec![];

    //select all tests that should run on this file
    for test in &config.tests {
        if test.runs_on_path(&path) {
            test_batch.push(test);
        }
    }

    let mut fail_counts = vec![0; test_batch.len()];

    for line in file_content.lines() {
        line_number += 1;

        if !in_class && config.class_regex.is_match(line) {
            in_class = true; //TODO actually *exit* classes too...
        }

        // TODO //add a tab at the start to make pre-whitespaces coherent
        let info = Info {
            path: path.to_path_buf(),
            line: Some(line_number),
            snippet: Some(line),
        };

        for i in 0..test_batch.len() {
            let test = &test_batch[i];
            if test.run(line, in_header, in_class) {
                fail_counts[i] += 1;

                //failure mode #1: we went over the exact count required
                if fail_counts[i] > test.expected_fails.exactly {
                    warnings.add(&test.error, &info);
                }
            }
        }
    }

    //failure mode #2: there were not enough failures. Ha!
    for i in 0..test_batch.len() {
        let test = &test_batch[i];
        if fail_counts[i] < test.expected_fails.exactly {
            let info = Info {
                path: path.to_path_buf(),
                line: None,
                snippet: None,
            };

            warnings.add(&test.error, &info);
        }
    }

    // if any warning was emitted, see if a blame file is present
    // in which case, attach the blame information to the warnings
    if warnings.len() > 0 {
        let blame_path = path.to_str().unwrap().to_owned() + ".blame";
        if let Ok(mut file) = File::open(blame_path) {
            file_content.clear();
            file.read_to_string(&mut file_content).unwrap();

            let lines: Vec<&str> = file_content.split('\n').collect();

            for (_, list) in &mut warnings.map {
                for w in list {
                    if let Some(line) = w.line {
                        w.blame = Some(lines[line].to_owned());
                    }
                }
            }
        }
    }

    warnings
}

fn run<W: Write>(
    config: Config,
    output: &mut W,
    replace_original_with_preprocessed: bool,
    ignore_safe: bool,
) -> usize {
    let mut paths: Vec<PathBuf> = vec![];
    let pool = ThreadPool::new(num_cpus::get());

    for root in &config.roots {
        walk(root.as_ref(), &mut paths);
    }

    let (sender, receiver) = mpsc::channel();

    let mut task_count = 0;
    for path in paths {
        if config.should_check(&path) {
            task_count += 1;
            let config = config.clone();
            let sender = sender.clone();

            pool.execute(move || {
                sender
                    .send(examine(
                        &config,
                        &path,
                        replace_original_with_preprocessed,
                        ignore_safe,
                    ))
                    .unwrap();
            });
        }
    }

    let warnings = receiver
        .iter()
        .take(task_count)
        .fold(Warnings::default(), |mut w, cur| {
            w.add_map(cur);
            w
        });

    let count = warnings.map.iter().fold(0, |c, (_, v)| c + v.len());
    write!(output, "{}", warnings).unwrap();
    if count == 1 {
        writeln!(output, "Found 1 issue!").unwrap();
    } else {
        writeln!(output, "Found {} issues!", count).unwrap();
    }
    count
}

fn open_output(maybe_path: Option<&str>) -> Box<Write> {
    if let Some(path) = maybe_path {
        if let Ok(file) = File::create(path) {
            return Box::new(file);
        }
        println!("Cannot open file at {}, defaulting to stdout", path);
    }

    return Box::new(io::stdout());
}

fn main() {
    const VERSION: &'static str = env!("CARGO_PKG_VERSION");

    let matches = App::new("A cpp linter")
        .version(VERSION)
        .about("Still pretty incomplete")
        .arg(Arg::with_name("JSON_PATH")
            .help("A JSON file containing the lints to apply to the program and the folders to \
                   scan")
            .value_name("Config File Path")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("root_path")
            .help("The folder where to look for the code. Omitting it will default to the Json \
                   file's folder")
            .value_name("Root path")
            .short("r")
            .long("root_path")
            .takes_value(true))
        .arg(Arg::with_name("output")
            .help("The path of the output file. Defaults to stdout if not provided.")
            .value_name("Output file")
            .short("o")
            .long("output")
            .takes_value(true))
        .arg(Arg::with_name("replace-original-with-preprocessed")
            .help("[dev option] Pass in this flag if you want to see what the intermediate files look like.")
            .long("replace-original-with-preprocessed"))
        .arg(Arg::with_name("ignore-safe")
            .help("Ignore /*safe*/ tags and show them anyway in the output")
            .long("ignore-safe"))
        .get_matches();

    let path = PathBuf::from(matches.value_of("JSON_PATH").unwrap());

    if !path.is_file() {
        println!("{} is not a file, or couldn't be found!", path.display());
        process::exit(1);
    }

    let rootpath = match matches.value_of("root_path") {
        Some(value) => PathBuf::from(value),
        None => to_absolute_path(&path)
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf(),
    };

    let replace_original_with_preprocessed =
        matches.is_present("replace-original-with-preprocessed");

    let ignore_safe = matches.is_present("ignore-safe");

    println!("Running acpplinter {}", VERSION);

    let mut output = open_output(matches.value_of("output"));

    if let Ok(mut file) = File::open(path.as_path()) {
        assert!(env::set_current_dir(rootpath).is_ok());

        let mut file_content = String::new();
        file.read_to_string(&mut file_content).unwrap();

        match json::decode::<ConfigDesc>(file_content.as_ref()) {
            Ok(desc) => {
                if run(
                    Config::from_desc(desc),
                    &mut output,
                    replace_original_with_preprocessed,
                    ignore_safe,
                ) == 0
                {
                    process::exit(0);
                } else {
                    process::exit(1);
                }
            }
            Err(e) => {
                println!("Invalid JSON");
                println!("{:?}", e);
            }
        }
    } else {
        println!("Cannot open config {}", path.display());
        process::exit(1);
    }
}
