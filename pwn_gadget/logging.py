class Color():
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def colored(text: str, color: str):
    return f"{color}{text}{Color.RESET}"

def cprint(text: str, color: str):
    print(f"{color}{text}{Color.RESET}")

class Logging():
    @staticmethod
    def info(string: str):
        print('[' + colored('*', Color.BLUE) + '] ' + string)

    @staticmethod
    def warn(string: str):
        print('[' + colored('!', Color.YELLOW) + '] ' + string)

    @staticmethod
    def error(string: str):
        print('[' + colored('ERROR', Color.RED) + '] ' + string)