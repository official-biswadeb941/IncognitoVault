# modules/captcha.py
import random

def generate_captcha():
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    operation = random.choice(['+', '-'])
    question = f"{num1} {operation} {num2}"
    answer = eval(question)
    return question, answer

def validate_captcha(user_answer, correct_answer):
    return user_answer == correct_answer
