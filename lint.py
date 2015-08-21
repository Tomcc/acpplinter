import re
import os
import shelve
import json
import sys
from sys import platform as _platform

if len(sys.argv) != 2 or not os.path.isfile(sys.argv[1]):
	print("Usage: py lint.py path/to/your/config.json")
	exit(1)

incremental = True
configPath = sys.argv[1]

warnings = {}

tests = []

def tryGet(json, key, default):
	try:
		return json[key]
	except:
		return default

def warn(msg, info):
	if not msg in warnings:
		warnings[msg] = []

	warnings[msg].append(info)

class Test:
	def __init__(self, desc):
		self.fail = []
		for string in desc["fail"]:
			self.fail.append(re.compile(string))

		self.allow = []
		for string in tryGet(desc, "allow", []):
			self.allow.append(re.compile(string))

		self.inClass = tryGet(desc, "classOnly", False)
		self.inHeader = tryGet(desc, "headerOnly", False)

		self.error = desc["error"]

	def run(self, line, isClassDefinition, isHeader, info):
		if (self.inClass and not isClassDefinition) or (self.inHeader and not isHeader):
			return

		for fail in self.fail:
			if fail.search(line):
				for allow in self.allow:
					if allow.search(line):
						return

				warn(self.error, info)
				return

classRegex = re.compile('\s+class\s+[^;]*$')
SAFE_TAG = '/*safe*/'


def exclude(path):
	for filter in excludeFilters:
		if filter.search(path):
			return True
	return False

def include(path):
	for filter in includeFilters:
		if filter.search(path):
			return True
	return False

def isChanged(path):
	newDate = os.path.getmtime(path)

	if incremental:
		try:
			oldDate = db[path]
			if newDate == oldDate:
				return False
		except:
			pass

	db[path] = newDate
	return True


def clean(buffer):
	result = ""
	
	STATE_CODE = 0
	STATE_SKIP_LINE = 1
	STATE_STRING = 2
	STATE_MULTILINE = 3

	state = STATE_CODE
	i = 0
	while i < len(buffer)-1:
		curr = buffer[i]
		next = buffer[i+1]

		if state == STATE_CODE:
			if curr == '/' and next == '/':
				state = STATE_SKIP_LINE
			elif curr == '"':
				state = STATE_STRING
			elif curr == '/' and next == '*' and buffer[i:i+len(SAFE_TAG)] != SAFE_TAG:
				state = STATE_MULTILINE
			else:
				result += curr
		elif state == STATE_SKIP_LINE:
			if next == '\n':
				state = STATE_CODE
		elif state == STATE_MULTILINE:
			if curr == '*' and next == '/':
				state = STATE_CODE
			elif next == '\n':
				result += curr
		elif state == STATE_STRING:
			if curr == '"':
				state = STATE_CODE

		i += 1

	return result

def getDefaultPath():
	if _platform == "linux" or _platform == "linux2":
	    return None
	elif _platform == "darwin":
		return os.path.expanduser("~") + "/Library/Application Support/acpplinter"
	elif _platform == "win32":
		return os.getenv('APPDATA') + "/acpplinter"

def examine(path):
	with open (path, "r", encoding='ascii') as myfile:
		count = 0
		allCommented = 0
		isClassDefinition = False
		isHeader = path.endswith('.h')

		try:
			buffer = clean(myfile.read())
		except UnicodeDecodeError as exc:
			warn("Non-ASCII characters detected in source file", (path, 0, str(exc)))
			return

		for line in buffer.splitlines():

			count += 1

			if SAFE_TAG in line:
				continue

			#add a tab at the start to make pre-whitespaces coherent
			line = '\t' + line

			info = (path, count, line)

			if not isClassDefinition and classRegex.search(line):
				isClassDefinition = True #it doesn't really know when it ends...

			for test in tests:
				test.run(line, isClassDefinition, isHeader, info)

def openShelve(path):
	try:
		os.mkdir(path)
	except:
		pass
	return shelve.open(path + "/files.db", 'c')

with open(configPath) as configFile:
	config = json.load(configFile)

	excludeFilters = []
	for e in config['excludes']:
		excludeFilters.append( re.compile(e) )

	includeFilters = []
	for i in config['includes']:
		includeFilters.append( re.compile(i) )

	for desc in config['tests']:
		tests.append(Test(desc))

	incremental = tryGet(config, 'incremental', False)
	dbPath = tryGet(config, 'dbpath', getDefaultPath())

with openShelve(dbPath) as db:

	#always recheck everything if the config or this file changed
	if incremental and isChanged(configPath) or isChanged(os.path.realpath(__file__)):
		incremental = False

	abspath = os.path.abspath(configPath)
	workdir = abspath[:abspath.replace("\\","/").rfind('/')+1]
	os.chdir(workdir)

	for root in config['roots']:
		print('Checking ' + root + '...')
		for root, dirs, files in os.walk(root):
			for file in files:
				fullpath = os.path.join(root,file)
				if include(fullpath) and not exclude(fullpath) and isChanged(fullpath):
					examine(fullpath)

count = 0
for warningType in warnings.items():
	print( "\n#### " + warningType[0])
	print()
	for detail in warningType[1]:
		file = detail[0][detail[0].rfind('\\')+1:]
		print("\t" + file + ":" + str(detail[1]) + "\t\t" + detail[2])
		count += 1

print("\nFound " + str(count) + " issues!\n")

if count == 0:
	exit(0)
else:
	exit(1)
