import re
import os
import shelve
import json
import sys

if len(sys.argv) != 2 or not os.path.isfile(sys.argv[1]):
	print("Usage: py lint.py path/to/your/config.json")
	exit(1)

incremental = True
configPath = sys.argv[1]

identifier = '[A-Za-z_][A-Za-z0-9_]*'
typeName = '[A-Z_][A-Za-z0-9_]*'

notid = '[^A-Za-z0-9_]+'

constructorRegEx = re.compile('^\s+' + typeName + '\(' + identifier + '[\*&]?\s*' + identifier + '\)\s*[{;]')
newRegEx = re.compile('\s+new\s+')
mallocRegex = re.compile(notid + 'malloc\s*\(.*\)\s*;')
deleteRegex = re.compile('\s+delete\s+')
allowedNewRegEx = re.compile('ref new\s+')
longRegEx = re.compile( notid + 'long' + notid )
allowedLongRegex = re.compile('long double')
longLongRegEx = re.compile( notid + 'long long' + notid )
constCastRegEx = re.compile('const_cast<.*>\(.*\)')
dynamicCastRegEx = re.compile('dynamic_cast<.*>\(.*\)')
stackRegEx = re.compile('std::stack')
xyzRegEx = re.compile('int\s+x\s+,\s+int\s+y\s+,\s+int\s+z')
xyzFloatRegEx = re.compile('float\s+x\s+,\s+float\s+y\s+,\s+float\s+z')
uniqueRefRegEx = re.compile('\(.*Unique<[^>]*>&[^&]')
commentBanner = re.compile('//--------')
startsWithComment = re.compile('^\s*//')
volatileRegEx = re.compile('\s+volatile\s+')
mutableRegex = re.compile('\s+mutable\s+')
inlineRegEx = re.compile('\s+inline\s+')
superUsageRegEx = re.compile('typedef.*super;')
virtualInlineRegex1 = re.compile('virtual.*inline')
virtualInlineRegex2 = re.compile('inline.*virtual')
passingStringsViaCopyRegex = re.compile('\(.*std::string[^&,*]+' + identifier + '.*\)')
constReferenceRegex = re.compile('const\s*&')
dangerousForAutoRegex = re.compile('for\s*\(\s*auto\s+' + identifier + '\s*:')
if0Regex = re.compile('#if\s+0')
classRegex = re.compile('\s+class\s+[^;]*$')
autoptrRegex = re.compile('auto_ptr')
constCharRegex = re.compile('const\s+char\s+\*')

SAFE_TAG = '/*safe*/'

warnings = {}

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


def warn(msg, info):
	if not msg in warnings:
		warnings[msg] = []

	warnings[msg].append(info)

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
			if (curr == '/' and next == '/') or curr == '#':
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
			if next == '"':
				state = STATE_CODE

		i += 1

	return result


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

			if isClassDefinition:
				if constructorRegEx.search(line) and not '/*implicit*/' in line:
					warn("Missing `explicit` keyword on possible conversion constructor", info)

				if virtualInlineRegex1.search(line) or virtualInlineRegex2.search(line):
					warn("virtual negates inline unless LTO and devirtualization is on? Explicitly include the code in the header if LTO fails", info)
				elif inlineRegEx.search(line):
					warn("inline doesn't do anything on modern compilers, just explicitly include the code in the header if desired", info)


			if isHeader:
				if constReferenceRegex.search(line):
					warn("Always place const before the type, pls!", info)
				elif passingStringsViaCopyRegex.search(line):
					warn("Passing strings via copy", info)

			if (newRegEx.search(line) and not allowedNewRegEx.search(line)) or deleteRegex.search(line):
				warn("Don't use new and delete, use a owning pointer or a container instead", info)

			if mallocRegex.search(line):
				warn("Don't use malloc(), try to use containers instead", info)

			if longLongRegEx.search(line):
				warn('Replace long long with int64_t', info)
			elif longRegEx.search(line) and not allowedLongRegex.search(line):
				warn('Use of inconsistent-length type long: use int64_t or int instead', info)

			if constCastRegEx.search(line):
				warn("Don't use const_cast, really :(", info)

			if dynamicCastRegEx.search(line):
				warn("dynamic_cast? RTTI is off!", info)

			if stackRegEx.search(line):
				warn("stack is non-contiguous and usually slower than a vector", info)

			if xyzRegEx.search(line) or xyzFloatRegEx.search(line):
				warn("Use a TilePos or a Vec3 instead", info)

			if uniqueRefRegEx.search(line):
				warn("Pass unique pointers by value, force the caller to move explicitly", info)

			if commentBanner.search(line):
				warn("Don't do comment banners pls", info)

			if volatileRegEx.search(line):
				warn("volatile doesn't mean what you think it means, use std::atomic<>", info)

			if superUsageRegEx.search(line):
				warn("Do not use super. It's a Java-ism that we're trying to get rid of", info)

			if dangerousForAutoRegex.search(line) and not 'range' in line:
				warn("Use plain for(auto : foo), always use for(auto&)! The first form can incur in lots of costly copies if the element type is non-primitive", info)

			if mutableRegex.search(line):
				warn("Avoid using mutable, like const_cast", info)

			if autoptrRegex.search(line):
				warn("Never use auto_ptr, upgrade to unique_ptr", info)

			if constCharRegex.search(line):
				warn("Don't use const char*, use std::string instead", info)

def openShelve(path):
	try:
		os.mkdir(path)
	except:
		pass
	return shelve.open(path + "/files.db", 'c')

def getKey(key, default):
	try:
		return config[key]
	except:
		return default

with open(configPath) as configFile:
	config = json.load(configFile)

	excludeFilters = []
	for e in config['excludes']:
		excludeFilters.append( re.compile(e) )

	includeFilters = []
	for i in config['includes']:
		includeFilters.append( re.compile(i) )

	incremental = getKey('incremental', False)
	dbPath = getKey('dbpath', os.getenv('APPDATA') + "/acpplinter")

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

