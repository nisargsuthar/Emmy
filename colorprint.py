import shutil
from colorama import Fore, Style

def print_centered_colored(text, color):
	terminal_width = shutil.get_terminal_size().columns
	colored_text = color + text + Style.RESET_ALL
	print(colored_text.center(terminal_width))