import re

###############################
# CANONICALIZATION FUNCTIONS: #
###################################################################################################################
def simple_header(headers):
	return '\n'.join(f"{name}:{value}" for name, value in headers.items())

def relaxed_header(headers):
	canonicalized_headers = []
	for name, value in headers.items():
		name = name.lower()
		value = value.replace('\r\n', ' ').replace('\r', ' ').replace('\n', ' ')
		value = ' '.join(value.split())
		value = value.strip()
		canonicalized_headers.append(f"{name.strip()}:{value}\r\n")
	return ''.join(canonicalized_headers)
###################################################################################################################
def simple_body(body):
	body = body.rstrip('\r\n')
	return body + '\r\n'

def relaxed_body(body):
	body = body.replace('\r\n', '\n').replace('\r', '\n').replace('\n', '\r\n')
	lines = body.split('\r\n')
	processed_lines = []
	for line in lines:
		line = line.rstrip()
		line = re.sub(r'[ \t]+', ' ', line)
		processed_lines.append(line)
	while processed_lines and processed_lines[-1] == '':
		processed_lines.pop()
	return '\r\n'.join(processed_lines) + '\r\n'
###################################################################################################################