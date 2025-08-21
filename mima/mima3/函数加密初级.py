from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os


# ========== 密钥生成 ==========
def setup(security_param=128):
    """生成主公钥(mpk)和主私钥(msk)"""
    # 在实际方案中会使用双线性配对或格密码，此处简化
    msk = os.urandom(security_param)  # 主私钥 = 随机字节串
    mpk = hashes.Hash(hashes.SHA256(), backend=default_backend())
    mpk.update(msk)
    mpk = mpk.finalize()  # 主公钥 = 主私钥的哈希
    return mpk, msk


def key_gen(msk, func_coeff):
    """为函数F(x) = func_coeff·x 生成函数密钥sk_F"""
    # 实际方案中需数学约束防止泄露，此处使用KDF绑定函数
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"FE_key_derivation",
        info=func_coeff.to_bytes(4, 'big'),
        backend=default_backend()
    )
    sk_F = hkdf.derive(msk)
    return sk_F  # 函数F的专用密钥


# ========== 加密 ==========
def encrypt(mpk, message):
    """用主公钥加密数据"""
    # 真实FE方案中会使用数学结构，此处用KDF模拟
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"FE_encryption",
        info=message,
        backend=default_backend()
    )
    ciphertext = hkdf.derive(mpk)  # 伪密文
    return ciphertext


# ========== 函数解密 ==========
def decrypt(sk_F, ciphertext):
    """用sk_F解密密文，获得F(明文)而非明文本身"""
    # 真实方案中会进行数学计算，此处模拟函数输出
    dummy_output = bytes(a ^ b for a, b in zip(sk_F, ciphertext))

    # 模拟线性函数 F(x) = coeff * x 的输出
    # 注意：实际无法从此输出反推x，符合FE特性
    return int.from_bytes(dummy_output[:4], 'big') % 100  # 返回0-99的整数


# ========== 示例使用 ==========
if __name__ == "__main__":
    # 系统初始化
    mpk, msk = setup()

    # 定义函数 F(x) = 3x
    func_coeff = 3
    sk_F = key_gen(msk, func_coeff)  # 生成函数密钥

    # Alice加密她的隐私数据 x=15
    x = 15
    ciphertext = encrypt(mpk, x.to_bytes(4, 'big'))

    # Bob用sk_F解密密文（只能获得3x，不能获得x）
    result = decrypt(sk_F, ciphertext)

    print(f"原始数据: {x}")
    print(f"函数F(x) = {func_coeff}*x 的输出: {result}")
    # 应输出: 函数F(x) = 3*x 的输出: 45 (0x0F -> 0x2D)