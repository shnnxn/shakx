from stream_cipher import user_text
from keydHash import input_message

def main():
    input_text = "Your plain text"
    hash_message = "Your hash message"
    input_message(hash_message)
    user_text(input_text)

main()
