import random
from PIL import Image, ImageDraw, ImageFont, ImageFilter

class CaptchaGenerator:
    def __init__(self, width=120, height=100, bg_color=(255, 255, 255), text_color=(0, 0, 0)):
        self.width = width
        self.height = height
        self.bg_color = bg_color
        self.text_color = text_color

    def generate_captcha(self):
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)
        operation = random.choice(['+', '-', '*'])
        question = f"{num1} {operation} {num2}"
        answer = eval(question)
        image = self.create_captcha_image(question)
        return image, answer

    def create_captcha_image(self, text):
        image = Image.new('RGB', (self.width, self.height), self.bg_color)
        draw = ImageDraw.Draw(image)
        font_size = 27
        font = ImageFont.load_default(font_size)  # Load default font
        text_x, text_y = 35, 15  # Position of the text
        draw.text((text_x, text_y), text, font=font, fill=self.text_color)
        image = self.apply_distortion(image)
        return image

    def apply_distortion(self, image, distortion_level=2.5):
        original_size = image.size
        draw = ImageDraw.Draw(image)
        num_lines = max(1, int(5 + distortion_level * 2))  # Ensure at least 1 line
        for _ in range(num_lines):
            start_point = (random.randint(0, image.width), random.randint(0, image.height))
            end_point = (random.randint(0, image.width), random.randint(0, image.height))
            line_color = (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
            draw.line([start_point, end_point], fill=line_color, width=1)
        blur_radius = distortion_level * 0.5 
        image = image.filter(ImageFilter.GaussianBlur(blur_radius))
        x_skew = 0.1 + distortion_level * 0.1
        y_skew = 0.1 + distortion_level * 0.05
        x_translate = 0  
        y_translate = 0 
        transformed_image = image.transform(
            original_size,
            Image.AFFINE,
            (1, x_skew, x_translate, y_skew, 1, y_translate)
        )
        return transformed_image

    def validate_captcha(self, user_answer, correct_answer):
        return user_answer == correct_answer

# Usage example
captcha = CaptchaGenerator()
