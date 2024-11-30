# This implementation of email authentication verification is compliant with RFC 6376 and assumes that the signing half was also compliant. This does not take care of any improper/non-compliant versions of DKIM implementations at the signer's end.

import email
import re
import dns.resolver
import dns.message
import dns.query
from dkimcanon import *
from colorprint import*
from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def parse_eml(msg):
	body = ""

	if msg.is_multipart():
		boundary = msg.get_boundary()
		boundary_str = f"--{boundary}\r\n" if boundary else ""
		end_boundary_str = f"--{boundary}--\r\n" if boundary else ""

		for part in msg.walk():
			content_type = part.get_content_type()
			if content_type not in ["text/plain", "text/html"]:
				continue
			if boundary_str:
				body += boundary_str
			for key, value in part.items():
				body += f"{key}: {value}\r\n"
			body += "\r\n"

			payload = part.get_payload(decode=True)
			if payload:
				charset = part.get_content_charset() or 'utf-8'
				payload = payload.decode(charset)
				payload = payload.replace('\r\n', '\n').replace('\r', '\n').replace('\n', '\r\n')
				body += payload
			body += "\r\n"

		if end_boundary_str:
			body += end_boundary_str
	else:
		payload = msg.get_payload(decode=True)
		if payload:
			charset = msg.get_content_charset() or 'utf-8'
			body = payload.decode(charset)

	# print(Fore.LIGHTBLUE_EX + "\nOriginal Body:\n" + Style.RESET_ALL, repr(body))
	return body


def extract_dkim_fields(dkim_header):
	fields = {}
	for field in dkim_header.split(';'):
		field = field.strip()
		if '=' in field:
			key, value = field.split('=', 1)
			fields[key] = value.replace('\n', '').replace(' ', '')
	# print(Fore.LIGHTBLUE_EX + "\nFields:\n" + Style.RESET_ALL, fields)
	return fields

def get_dkim_public_key(dkim_fields):
	domain = dkim_fields['d']
	selector = dkim_fields['s']
	# print(Fore.LIGHTBLUE_EX + "\nDomain & Selector:\n" + Style.RESET_ALL, domain, selector)

	dkim_record = f'{selector}._domainkey.{domain}'
	print(Fore.LIGHTCYAN_EX + "\nDKIM Query String:\n" + Style.RESET_ALL, dkim_record)
	
	try:
		query = dns.message.make_query(dkim_record, 'TXT')
		response = dns.query.tcp(query, '1.1.1.1')
		key_parts = []

		for answer in response.answer:
			for txt_string in answer.items:
				txt_record = txt_string.to_text()
				if 'p=' not in txt_record:
					continue
				if txt_record:
					key_parts.append(txt_record.strip('"'))

		full_key = ''.join(key_parts)
		print(Fore.LIGHTBLUE_EX + "\nTXT Record:\n" + Style.RESET_ALL, full_key)
		if 'p=' in full_key:
			key_parts = dict(item.strip().split('=', 1) for item in full_key.split(';') if '=' in item)
			public_key_b64 = key_parts['p']
			public_key_pem = (
				f"-----BEGIN PUBLIC KEY-----\n"
				f"{public_key_b64}\n"
				f"-----END PUBLIC KEY-----\n"
			).encode("ascii")
			return public_key_pem
	except dns.resolver.NoAnswer:
		print(Fore.LIGHTYELLOW_EX + f"\nNo DKIM record found for {dkim_record}\n" + Style.RESET_ALL)
	except Exception as e:
		print(Fore.LIGHTRED_EX + f"\nError fetching DKIM record: {e}\n" + Style.RESET_ALL)
	return None

def verify_rsa_signature(dkim_fields, body, dkim_header_counter, public_key, hash_alg, msg):
	if "c" in dkim_fields:
		canonicalization = dkim_fields['c']
		print(Fore.LIGHTBLUE_EX + "\nCanonicalization:\n" + Style.RESET_ALL, canonicalization)
		header_canonicalization, body_canonicalization = canonicalization.split("/")
	else:
		header_canonicalization =  body_canonicalization = "simple"
#######################################################################################################
	# STEP 1 #
	##########
	canonicalized_body = simple_body(body) if body_canonicalization == 'simple' else relaxed_body(body)
	# print(Fore.LIGHTBLUE_EX + "\nCanonicalized Body:\n" + Style.RESET_ALL, repr(canonicalized_body),"\n")

	body_hasher = hashes.Hash(hashes.SHA256() if hash_alg == 'sha256' else hashes.SHA1(), backend=default_backend())
	body_hasher.update(canonicalized_body.encode())
	generated_body_hash = b64encode(body_hasher.finalize()).decode()

	if dkim_header_counter == 1:
		print(Fore.LIGHTCYAN_EX + "\nBody Hash Comparison:" + Style.RESET_ALL)
		color = Fore.LIGHTGREEN_EX if generated_body_hash == dkim_fields['bh'] else Fore.LIGHTRED_EX
		print_centered_colored("###############################################################", color)
		print_centered_colored("Computed >>> " + generated_body_hash, color)
		print_centered_colored("bh field >>> " + dkim_fields['bh'], color)
		print_centered_colored("###############################################################", color)
	
	if generated_body_hash != dkim_fields['bh']:
		return False
#######################################################################################################
	# STEP 2 #
	##########
	signed_headers = dkim_fields['h'].split(':')
	headers_to_sign = {}
	# print(Fore.LIGHTBLUE_EX + "\nSigned Headers:\n" + Style.RESET_ALL, signed_headers)
	for header in signed_headers:
		if header in msg:
			headers_to_sign[header] = msg[header]
	canonicalized_header = simple_header(headers_to_sign) if header_canonicalization == 'simple' else relaxed_header(headers_to_sign)
	print(Fore.LIGHTBLUE_EX + "\nCanonicalized Header:\n" + Style.RESET_ALL, repr(canonicalized_header))
#######################################################################################################
	# STEP 3 #
	##########
	dkim_signature_header=""
	for dkim_field, dkim_value in dkim_fields.items():
		dkim_signature_header += dkim_field + "=" + dkim_value + "; "
	dkim_signature_header = "dkim-signature:"+re.sub(r"(b=)[^;]*", r"\1", dkim_signature_header).strip()[:-1]
	print(Fore.LIGHTBLUE_EX + "\nDKIM-Signature Header:\n" + Style.RESET_ALL, repr(dkim_signature_header))

	canonicalized_header += dkim_signature_header
	print(Fore.LIGHTBLUE_EX + "\nFinal Headers:\n" + Style.RESET_ALL, repr(canonicalized_header))
   
	message_to_verify = canonicalized_header

	public_key_obj = serialization.load_pem_public_key(public_key, backend=default_backend())

	if hash_alg == 'sha256':
		hash_algorithm = hashes.SHA256()
	elif hash_alg == 'sha1':
		hash_algorithm = hashes.SHA1()
	else:
		raise ValueError(Fore.LIGHTYELLOW_EX + f"\nUnsupported hash algorithm: {hash_alg}\n" + Style.RESET_ALL)

	signature = b64decode(dkim_fields['b'])
	# print("SIGNATURE: ", signature)
	try:
		public_key_obj.verify(
			signature,
			message_to_verify.encode(),
			padding.PKCS1v15(),
			hash_algorithm
		)
		return True
	except InvalidSignature as e:
		print(Fore.LIGHTRED_EX + f"\nVerification failed: {e}" + Style.RESET_ALL)
		return False

def verify_dkim_signature(dkim_fields, body, dkim_header_counter, public_key, msg):
	algorithm = dkim_fields.get('a', 'rsa-sha256')
	if algorithm == 'rsa-sha256':
		return verify_rsa_signature(dkim_fields, body, dkim_header_counter, public_key, 'sha256', msg)
	elif algorithm == 'rsa-sha1':
		return verify_rsa_signature(dkim_fields, body, dkim_header_counter, public_key, 'sha1', msg)
	else:
		print(Fore.LIGHTRED_EX + f"Unsupported DKIM signature algorithm: {algorithm}" + Style.RESET_ALL)
		return False

def verify_eml_dkim(msg):
	print_centered_colored("########################################################################################################", Fore.MAGENTA)
	print_centered_colored("# DKIM VERIFICATION #", Fore.LIGHTMAGENTA_EX)
	print_centered_colored("########################################################################################################", Fore.MAGENTA)
	dkim_headers = msg.get_all('DKIM-Signature', [])
	body = parse_eml(msg)

	dkim_passed = False
	dkim_header_counter = 0
	for dkim_header in dkim_headers:
		dkim_header_counter += 1
		print(Fore.LIGHTYELLOW_EX + f"\nProcessing DKIM Header {dkim_header_counter}...\n" + Style.RESET_ALL)
		print(Fore.LIGHTBLUE_EX + "\nDKIM Header:\n" + Style.RESET_ALL, repr(dkim_header))
		dkim_fields = extract_dkim_fields(dkim_header)
		public_key = get_dkim_public_key(dkim_fields)
		print(Fore.LIGHTBLUE_EX + "\nPublic Key:\n" + Style.RESET_ALL, public_key)
		
		if dkim_header_counter == 1:
			dkim_header_domain = dkim_fields['d']

		if public_key:
			if verify_dkim_signature(dkim_fields, body, dkim_header_counter, public_key, msg):
				print(Fore.LIGHTGREEN_EX + "\n!! DKIM Verification Passed !!\n" + Style.RESET_ALL)
				dkim_passed = True
			else:
				print(Fore.LIGHTRED_EX + "\n!! DKIM Verification Failed !!\n" + Style.RESET_ALL)
		else:
			print(Fore.LIGHTYELLOW_EX + "\nFailed to retrieve DKIM public key." + Style.RESET_ALL)

	return dkim_passed, dkim_header_domain