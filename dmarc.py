from colorprint import*
from publicsuffixlist import PublicSuffixList
import dns.resolver
import dns.message
import dns.query

def relaxed_alignment(from_header_domain, domain):
	psl = PublicSuffixList()
	return True if psl.privatesuffix(from_header_domain) == psl.privatesuffix(domain) else False

def verify_eml_dmarc(spf_passed, dkim_passed, from_header_domain, return_path_domain, dkim_header_domain):
	def print_from_header(color):
		print_centered_colored("From Header Domain >>> " + from_header_domain, color)
	def print_return_path(color):
		print_centered_colored("Return-Path Header Domain >>> " + return_path_domain, color)
	def print_dkim_header(color):
		print_centered_colored("DKIM-Signature Header Domain >>> " + dkim_header_domain, color)
	def print_line(color):
		print_centered_colored("###############################################################", color)

	print_centered_colored("########################################################################################################", Fore.MAGENTA)
	print_centered_colored("# DMARC VERIFICATION #", Fore.LIGHTMAGENTA_EX)
	print_centered_colored("########################################################################################################", Fore.MAGENTA)
###########################################################################################################

	if spf_passed or dkim_passed:
		dmarc_record = f'_dmarc.{from_header_domain}'
		print(Fore.LIGHTCYAN_EX + "\nDMARC Query String:\n" + Style.RESET_ALL, dmarc_record)
		aspf = adkim = "r"
		spf_aligned = dkim_aligned = False
		try:
			query = dns.message.make_query(dmarc_record, 'TXT')
			response = dns.query.tcp(query, '1.1.1.1')
			for answer in response.answer:
				for txt_string in answer.items:
					txt_record = txt_string.to_text().strip('"')
					if "v=DMARC1" in txt_record:
						print(Fore.LIGHTBLUE_EX + "\nTXT Record:\n" + Style.RESET_ALL, txt_record)
						for field in txt_record.split(";"):
							field = field.strip()
							if "aspf" in field:
								aspf = field.split("=")[-1]
							if "adkim" in field:
								adkim = field.split("=")[-1]
		except dns.resolver.NoAnswer:
			print(Fore.LIGHTYELLOW_EX + f"\nNo DMARC record found for {dmarc_record}\n" + Style.RESET_ALL)
		except Exception as e:
			print(Fore.LIGHTRED_EX + f"\nError fetching DMARC record: {e}\n" + Style.RESET_ALL)

		print(Fore.LIGHTBLUE_EX + "\nAlignment Policies:\n" + Style.RESET_ALL, aspf+" "+adkim)

		if spf_passed:
			if aspf == "r":
				if relaxed_alignment(from_header_domain, return_path_domain):
					spf_aligned = True
			else:
				if from_header_domain == return_path_domain:
					spf_aligned = True
		if dkim_passed:
			if adkim == "r":
				if relaxed_alignment(from_header_domain, dkim_header_domain):
					dkim_aligned = True
			else:
				if from_header_domain == dkim_header_domain:
					dkim_aligned = True

		if spf_aligned or dkim_aligned:
			print(Fore.LIGHTGREEN_EX + "\n!! DMARC Verification Passed !!\n" + Style.RESET_ALL)
			c = Fore.LIGHTGREEN_EX
			spf_alignment = "relaxed" if aspf == "r" else "strict"
			dkim_alignment = "relaxed" if adkim == "r" else "strict"
			if spf_aligned and dkim_aligned:
				print(c + f"(via both SPF [{spf_alignment}] and DKIM [{dkim_alignment}])\n" + Style.RESET_ALL)
				print_line(c)
				print_return_path(c)
				print_from_header(c)
				print_dkim_header(c)
				print_line(c)
			else:
				only_aligned = "SPF" if spf_aligned else "DKIM"
				print(c + f"(via {only_aligned} [{spf_alignment if spf_aligned else dkim_alignment}] alignment)\n" + Style.RESET_ALL)
				print_line(c)
				print_from_header(c)
				print_return_path(c) if spf_aligned else print_dkim_header(c)
				print_line(c)
			print("\n")
	else:
		c = Fore.LIGHTRED_EX
		print(Fore.LIGHTRED_EX + "\n!! DMARC Verification Failed !!\n" + Style.RESET_ALL)
		print_line(c)
		print_return_path(c)
		print_from_header(c)
		print_dkim_header(c)
		print_line(c)	