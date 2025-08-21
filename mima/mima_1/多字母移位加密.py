import random
import string


def generate_key(length=16):
    """生成指定长度的随机大写字母密钥"""
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))


def encrypt(plaintext, key):
    """多字母移位加密"""
    if not key.isalpha():
        raise ValueError("密钥必须仅包含字母字符")

    ciphertext = []
    key = key.upper()  # 统一转换为大写处理
    key_length = len(key)
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            # 计算当前字母的移位值
            shift = ord(key[key_index % key_length]) - ord('A')

            # 处理字母移位
            if char.isupper():
                new_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                new_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))

            ciphertext.append(new_char)
            key_index += 1  # 仅字母字符消耗密钥位置
        else:
            ciphertext.append(char)  # 非字母字符直接保留

    return ''.join(ciphertext)


def decrypt(ciphertext, key):
    """多字母移位解密"""
    if not key.isalpha():
        raise ValueError("密钥必须仅包含字母字符")

    plaintext = []
    key = key.upper()  # 统一转换为大写处理
    key_length = len(key)
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            # 计算当前字母的移位值
            shift = ord(key[key_index % key_length]) - ord('A')

            # 处理反向移位
            if char.isupper():
                new_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                new_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))

            plaintext.append(new_char)
            key_index += 1  # 仅字母字符消耗密钥位置
        else:
            plaintext.append(char)  # 非字母字符直接保留

    return ''.join(plaintext)


# 使用示例
if __name__ == "__main__":
    # 生成随机密钥
    key = generate_key(5)
    print(f"生成的密钥: {key}")

    # 原始文本
    plaintext = "Hello, World! 2025"
    print(f"原始文本: {plaintext}")

    # 加密
    encrypted = encrypt(plaintext, key)
    print(f"加密结果: {encrypted}")

    # 解密
    decrypted = decrypt(encrypted, key)
    print(f"解密结果: {decrypted}")