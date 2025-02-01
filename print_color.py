import random


class Colorpr:
    @staticmethod
    def color_red(test):
        return f"\033[1;31m{test}\033[0m"

    @staticmethod
    def color_red_bd(test):
        return f"[\033[1;31m+\033[0m] {test}"

    @staticmethod
    def color_blue_bd(test):
        return f"[\033[34m-\033[0m] {test}"

    @staticmethod
    def color_blue(test):
        return f"\033[34m{test}\033[0m"

    @staticmethod
    def color_yellow(test):
        return f"\033[33m{test}\033[0m"

    @staticmethod
    def color_purple(test):
        return f"\033[35m{test}\033[0m"

    def color_random(self, test):
        color_functions = [self.color_purple, self.color_red, self.color_red, self.color_blue]
        random_color_function = random.choice(color_functions)
        return random_color_function(test)

    def color_title(self):

        description_data = fr"""
    .__       .  .         .    
    |  \ _.._.|_/ ._ . . _.| _ *
    |__/(_][  |  \[ )(_|(_.|(/,| 
    DarKnuclei Beta v2.0 by RuoJi
        """
        color_functions = [self.color_red, self.color_purple, self.color_red, self.color_red, self.color_blue, self.color_red, self.color_blue]
        random_color_function = random.choice(color_functions)
        return random_color_function(description_data)
