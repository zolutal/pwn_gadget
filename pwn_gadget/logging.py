from termcolor import colored

class Logging():
    @staticmethod
    def info(string: str):
        print('[' + colored('*', 'blue') + '] ' + string)

    @staticmethod
    def warn(string: str):
        print('[' + colored('!', 'yellow') + '] ' + string)