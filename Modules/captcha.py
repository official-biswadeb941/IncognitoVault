import random
from PIL import Image, ImageDraw, ImageFont, ImageFilter

def generate_captcha():
    # Generate random numbers and operation
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    operation = random.choice(['+', '-','*'])
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

    font_size = 30
    # Load a font
    font = ImageFont.load_default(font_size)

    # Calculate bounding box of the text to center it
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width, text_height = bbox[2] - bbox[0], bbox[3] - bbox[1]
    text_x = 35
    text_y = 20

    # Draw the text on the image
    draw.text((text_x, text_y), text, font=font, fill=text_color)

    # Apply some distortions and noise
    image = apply_distortion(image)
    return image

def apply_distortion(image, distortion_level=2.5):
    # Create a copy of the original image to avoid modifying it directly
    original_size = image.size
    draw = ImageDraw.Draw(image)

    # Number of lines based on distortion level (integer or float)
    num_lines = max(1, int(5 + distortion_level * 2))  # Ensure at least 1 line
    for _ in range(num_lines):
        start_point = (random.randint(0, image.width), random.randint(0, image.height))
        end_point = (random.randint(0, image.width), random.randint(0, image.height))
        line_color = (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        draw.line([start_point, end_point], fill=line_color, width=1)

    # Apply filters to create distortion, adjusted for distortion level
    blur_radius = distortion_level * 0.5  # Increase blur with distortion level
    image = image.filter(ImageFilter.GaussianBlur(blur_radius))

    # Adjust the affine transform parameters based on distortion level
    x_skew = 0.1 + distortion_level * 0.1
    y_skew = 0.1 + distortion_level * 0.05
    x_translate = 0  # No translation to prevent size change
    y_translate = 0  # No translation to prevent size change

    # Apply the affine transformation with clamped size
    transformed_image = image.transform(
        original_size,  # Keep the original size
        Image.AFFINE,
        (1, x_skew, x_translate, y_skew, 1, y_translate)
    )

    return transformed_image

def validate_captcha(user_answer, correct_answer):
    return user_answer == correct_answer
