import hashlib
import hmac
from datetime import datetime
from datetime import timezone
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Generate RSA key pair for digital signature
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

def generate_signature(message, private_key):
    signer = pkcs1_15.new(RSA.import_key(private_key))
    signature = signer.sign(SHA256.new(message))
    return signature

def verify_signature(message, signature, public_key):
    verifier = pkcs1_15.new(RSA.import_key(public_key))
    try:
        verifier.verify(SHA256.new(message), signature)
        return True
    except (ValueError, TypeError):
        return False

def generate_mac(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

    # Generate timestamp variable
def generate_timestamp():
    return datetime.now(timezone.utc)

# Append timestamp to original message to create 'protect_message' variable
def protect_message(message):
    timestamp = generate_timestamp()

    # Generate HMAC
    hmac_key = b'SecretKey'
    mac = generate_mac(hmac_key, message)

    # Combine message, HMAC, and timestamp
    protected_message = {
        'message': message,
        'hash_code': hashlib.sha256(message.encode()).hexdigest(),
        'mac': mac,
        'timestamp': timestamp
    }

    # Generate digital signature
    signature = generate_signature(message.encode(), private_key)

    return protected_message, signature

def verify_message(protected_message, signature):
    # Verify digital signature
    if not verify_signature(protected_message['message'].encode(), signature, public_key):
        return False

    # Verify HMAC
    hmac_key = b'SecretKey'
    calculated_mac = generate_mac(hmac_key, protected_message['message'])
    if calculated_mac != protected_message['mac']:
        return False

    # Check timestamp validity (within 60 seconds)
    message_time = protected_message['timestamp']
    current_time = datetime.now(timezone.utc)
    if abs(current_time - message_time).seconds > 60:
        return False

    # Verify hash code
    if hashlib.sha256(protected_message['message'].encode()).hexdigest() != protected_message['hash_code']:
        return False

    return True

# Main
if __name__ == "__main__":
    message = ("The company website has not limited the number of transactions a single user "
               "or device can perform in a given period of time. The transactions/time should "
               "be above the actual business requirement, but low enough to deter automated attacks.")

    # Protect the message
    protected_message, signature = protect_message(message)
    print("Protected Message:")
    print("Plain Text:", protected_message['message'])
    print("Hash Code:", protected_message['hash_code'])
    print("HMAC:", protected_message['mac'])
    # this is python string interpolation
    print(f"Timestamp: {protected_message['timestamp']}")
    print("Signature", signature)
    result_vs = verify_signature(protected_message['message'].encode(), signature, public_key)
    print("Signature verification result:", result_vs)
    result_vm = verify_message(protected_message, signature)
    print("Digital Signature Verification Result:", result_vm)
    hmac_key = b'SecretKey'
    calculated_mac = generate_mac(hmac_key, protected_message['message'])
    result_cm = (calculated_mac == protected_message['mac'])
    print("Calculated MAC:", calculated_mac)
    print(f"protected_message['mac']: {protected_message['mac']}")
    print("HMAC verification result:", result_cm)
    calculated_hash_code = hashlib.sha256(protected_message['message'].encode()).hexdigest()
    result_ch = (calculated_hash_code == protected_message['hash_code'])
    print("Calculated hash code verified:", result_ch)
    print()

    # Verify the message
    if verify_message(protected_message, signature):
        print("Message is authentic.")
    else:
        print("Message authentication failed.")
