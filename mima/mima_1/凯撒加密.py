# 1.从密钥空间中选取密钥
# 2.加密函数：输入原文，密钥，输出密文
# 3.解密函数：输入密文，密钥输出原文。

import random


def generate_key():
    """生成一个0到25之间的随机密钥"""
    return random.randint(0, 25)


def encrypt(plaintext, key):
    """使用凯撒密码加密明文"""
    ciphertext = []
    for char in plaintext:
        if char.isupper():
            # 处理大写字母
            shifted = (ord(char) - ord('A') + key) % 26
            ciphertext.append(chr(shifted + ord('A')))
        elif char.islower():
            # 处理小写字母
            shifted = (ord(char) - ord('a') + key) % 26
            ciphertext.append(chr(shifted + ord('a')))
        else:
            # 非字母字符保持不变
            ciphertext.append(char)
    return ''.join(ciphertext)


def decrypt(ciphertext, key):
    """使用凯撒密码解密密文"""
    plaintext = []
    for char in ciphertext:
        if char.isupper():
            shifted = (ord(char) - ord('A') - key) % 26
            plaintext.append(chr(shifted + ord('A')))
        elif char.islower():
            shifted = (ord(char) - ord('a') - key) % 26
            plaintext.append(chr(shifted + ord('a')))
        else:
            # 非字母字符保持不变
            plaintext.append(char)
    return ''.join(plaintext)


# 示例用法
if __name__ == "__main__":
    # 生成密钥
    key = generate_key()
    print("生成的密钥:", key)

    # 原始文本
    plaintext = "Hello, World! 2025"
    print("原始文本:", plaintext)

    # 加密
    encrypted = encrypt(plaintext, key)
    print("加密结果:", encrypted)

    # 解密
    decrypted = decrypt(encrypted, key)
    print("解密结果:", decrypted)