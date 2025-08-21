import random


def generate_key():
    """生成包含大小写字母替换规则的加密密钥"""
    # 生成大写字母替换表
    upper_chars = [chr(i) for i in range(ord('A'), ord('Z') + 1)]
    shuffled_upper = upper_chars.copy()
    random.shuffle(shuffled_upper)

    # 生成小写字母替换表
    lower_chars = [chr(i) for i in range(ord('a'), ord('z') + 1)]
    shuffled_lower = lower_chars.copy()
    random.shuffle(shuffled_lower)

    # 构建加密字典
    encryption_key = {}
    for uc, sc in zip(upper_chars, shuffled_upper):
        encryption_key[uc] = sc
    for lc, slc in zip(lower_chars, shuffled_lower):
        encryption_key[lc] = slc
    return encryption_key


def encrypt(plaintext, key):
    """使用替换密码加密文本"""
    ciphertext = []
    for char in plaintext:
        ciphertext.append(key.get(char, char))  # 非字母字符保持不变
    return ''.join(ciphertext)


def decrypt(ciphertext, key):
    """使用替换密码解密文本"""
    decryption_key = {v: k for k, v in key.items()}  # 创建反向映射
    plaintext = []
    for char in ciphertext:
        plaintext.append(decryption_key.get(char, char))
    return ''.join(plaintext)


# 示例用法
if __name__ == "__main__":
    # 生成密钥
    key = generate_key()
    print("加密密钥示例（部分）:", {k: key[k] for k in list(key.keys())[:5]})

    # 原始文本
    plaintext = "Hello, World! 2025"
    print("\n原始文本:", plaintext)

    # 加密
    encrypted = encrypt(plaintext, key)
    print("加密结果:", encrypted)

    # 解密
    decrypted = decrypt(encrypted, key)
    print("解密结果:", decrypted)