from spf import *
from dkim import *
from dmarc import *

with open('vercel.eml', 'rb') as f:
	msg = email.message_from_binary_file(f)

spf_passed, from_header_domain, return_path_domain = verify_eml_spf(msg)
dkim_passed, dkim_header_domain = verify_eml_dkim(msg)
verify_eml_dmarc(spf_passed, dkim_passed, from_header_domain, return_path_domain, dkim_header_domain)