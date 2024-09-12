# modules/captcha.py

import random
from PIL import Image, ImageDraw, ImageFont, ImageFilter

def generate_captcha():
    # Generate random numbers and operation
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    operation = random.choice(['+', '-'])
    question = f"{num1} {operation} {num2}"
    answer = eval(question)
    
    # Create an image with the question
    image = create_captcha_image(question)
    return image, answer

def create_captcha_image(text):
    # Set up image size and background color
    width, height = 120, 100
    background_color = (255, 255, 255)  # white background
    text_color = (0, 0, 0)  # black text

    # Create a blank image with white background
    image = Image.new('RGB', (width, height), background_color)
    draw = ImageDraw.Draw(image)

    # Load a font
    font = ImageFont.load_default()

    # Calculate bounding box of the text to center it
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width, text_height = bbox[2] - bbox[0], bbox[3] - bbox[1]
    text_x = (width - text_width) // 2
    text_y = (height - text_height) // 2

    # Draw the text on the image
    draw.text((text_x, text_y), text, font=font, fill=text_color)

    # Apply some distortions and noise
    image = apply_distortion(image)
    return image

def apply_distortion(image):
    # Add some random lines
    draw = ImageDraw.Draw(image)
    for _ in range(8):
        start_point = (random.randint(0, image.width), random.randint(0, image.height))
        end_point = (random.randint(0, image.width), random.randint(0, image.height))
        line_color = (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        draw.line([start_point, end_point], fill=line_color, width=1)
    
    # Apply filters to create distortion
    image = image.filter(ImageFilter.GaussianBlur(1))  # Slight blur
    image = image.transform((120, 60), Image.AFFINE, (1, 0.3, -10, 0.1, 1, -5))  # Apply affine transform
    return image

def validate_captcha(user_answer, correct_answer):
    return user_answer == correct_answer
