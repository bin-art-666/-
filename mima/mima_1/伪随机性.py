import hashlib
import hmac
import secrets


def PRG(key: bytes, length: int) -> bytes:
    """伪随机发生器，使用HMAC-SHA256扩展密钥流"""
    output = b''
    counter = 0
    while len(output) < length:
        # 使用HMAC-SHA256和计数器生成确定性输出
        h = hmac.new(key, counter.to_bytes(4, 'big'), hashlib.sha256)
        output += h.digest()  # 每次生成32字节
        counter += 1
    return output[:length]  # 截取所需长度


def generate_key(n_bits: int) -> bytes:
    """生成n位的随机密钥（n需为8的倍数）"""
    if n_bits % 8 != 0:
        raise ValueError("密钥长度必须是8的倍数")
    return secrets.token_bytes(n_bits // 8)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """加密：明文与PRG生成的密钥流异或"""
    keystream = PRG(key, len(plaintext))
    ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
    return ciphertext


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """解密：密文与PRG生成的密钥流异或（与加密过程相同）"""
    return encrypt(key, ciphertext)


# 示例用法
if __name__ == "__main__":
    # 生成128位密钥（16字节）
    key = generate_key(128)
    plaintext = b"Hello, World!"

    # 加密
    ciphertext = encrypt(key, plaintext)
    print("密文:", ciphertext.hex())

    # 解密
    decrypted = decrypt(key, ciphertext)
    print("解密结果:", decrypted.decode())