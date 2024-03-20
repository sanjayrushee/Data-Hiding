from stegano import lsb
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Create a 128-bit encryption key
key = get_random_bytes(16)

def encrypt_content(content, password):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(content)
    return nonce + tag + ciphertext

def decrypt_content(encrypted_content, password):
    nonce = encrypted_content[:16]
    tag = encrypted_content[16:32]
    ciphertext = encrypted_content[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_content = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_content

def store_content(image_path, content, password):
    try:
        encrypted_content = encrypt_content(content.encode(), password.encode())
        secret_image = lsb.hide(image_path, encrypted_content)
        secret_image.save("sm2.png", quality=5)
        print("Content hidden successfully!")
    except Exception as e:
        print(f"Error: {e}")

def retrieve_content(image_path, password):
    try:
        original_image = Image.open(image_path)
        encrypted_content = lsb.reveal(original_image)
        decrypted_content = decrypt_content(encrypted_content, password.encode()).decode('utf-8')
        print("Decrypted Content:", decrypted_content)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    action = input("Enter action (store/retrieve): ").lower()
    image_path = input("Enter path to the image: ")
    password = input("Enter password: ")

    if action == "store":
        content = input("Enter content to hide: ")
        store_content(image_path, content, password)
    elif action == "retrieve":
        retrieve_content(image_path, password)
    else:
        print("Invalid action. Please enter 'store' or 'retrieve'.")
