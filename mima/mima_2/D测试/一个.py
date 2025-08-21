import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple
import secrets


class BilinearGroup:
    """双线性群实现（基于配对友好曲线）"""

    def __init__(self, curve=ec.SECP256R1):
        self.curve = curve
        self.backend = default_backend()

    def generate_group_params(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, bytes]:
        """生成主密钥、公共参数和群生成元"""
        private_key = ec.generate_private_key(self.curve(), self.backend)
        public_key = private_key.public_key()

        # 使用曲线的标准基点作为生成元
        generator = self.curve().generator
        generator_bytes = generator.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        return private_key, public_key, generator_bytes

    def bilinear_map(self, P: bytes, Q: bytes) -> bytes:
        """实现双线性映射e(P, Q)，模拟配对计算"""
        return hashlib.sha256(P + Q).digest()


def generate_random_point(curve: ec.EllipticCurve) -> bytes:
    """生成随机椭圆曲线点并序列化"""
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )


def demo_bilinear_group():
    print("=" * 60)
    print("双线性群演示")
    print("=" * 60)

    # 创建双线性群实例
    bilinear_group = BilinearGroup()

    # 生成群参数
    private_key, public_key, generator_bytes = bilinear_group.generate_group_params()

    print("\n[1] 群参数生成结果:")
    print(f"私钥长度: {len(private_key.private_bytes(serialization.Encoding.DER,
                                                     serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))} 字节")
    print(f"公钥长度: {len(public_key.public_bytes(serialization.Encoding.X962,
                                                   serialization.PublicFormat.UncompressedPoint))} 字节")
    print(f"生成元长度: {len(generator_bytes)} 字节")

    # 生成两个随机点P和Q
    curve = ec.SECP256R1()
    P_bytes = generate_random_point(curve)
    Q_bytes = generate_random_point(curve)

    print("\n[2] 随机点生成:")
    print(f"点P: {P_bytes[:10]}... (长度: {len(P_bytes)} 字节)")
    print(f"点Q: {Q_bytes[:10]}... (长度: {len(Q_bytes)} 字节)")

    # 计算双线性映射 e(P, Q)
    e_PQ = bilinear_group.bilinear_map(P_bytes, Q_bytes)

    # 计算双线性映射 e(P, P)
    e_PP = bilinear_group.bilinear_map(P_bytes, P_bytes)

    # 计算双线性映射 e(Q, Q)
    e_QQ = bilinear_group.bilinear_map(Q_bytes, Q_bytes)

    print("\n[3] 双线性映射结果:")
    print(f"e(P, Q): {e_PQ.hex()}")
    print(f"e(P, P): {e_PP.hex()}")
    print(f"e(Q, Q): {e_QQ.hex()}")

    # 验证双线性性质（模拟）
    print("\n[4] 双线性性质验证（模拟）:")

    # 生成标量 a 和 b
    a = secrets.randbelow(1000) + 1
    b = secrets.randbelow(1000) + 1
    print(f"标量 a = {a}, b = {b}")

    # 计算 e(aP, bQ) 和 e(P, Q)^{a*b}
    # 在实际双线性配对中，应该有：e(aP, bQ) = e(P, Q)^{a*b}

    # 由于我们使用哈希模拟，这里展示计算过程但结果不会真正相等
    # 在实际密码学中，应该使用支持配对的曲线如BN254

    # 计算 aP 和 bQ
    # 在实际实现中，这需要在椭圆曲线上进行点乘
    # 这里我们简单地将标量转换为字节并连接
    aP_bytes = P_bytes + a.to_bytes(4, 'big')
    bQ_bytes = Q_bytes + b.to_bytes(4, 'big')

    e_aP_bQ = bilinear_group.bilinear_map(aP_bytes, bQ_bytes)

    # 计算 e(P, Q)^{a*b}
    e_PQ_bytes = bilinear_group.bilinear_map(P_bytes, Q_bytes)
    e_PQ_ab = hashlib.sha256(e_PQ_bytes * (a * b)).digest()

    print(f"e(aP, bQ): {e_aP_bQ.hex()}")
    print(f"e(P, Q)^{a * b}: {e_PQ_ab.hex()}")

    # 验证结果是否相等（在真实双线性配对中应该相等）
    if e_aP_bQ == e_PQ_ab:
        print("✅ 双线性性质成立!")
    else:
        print("❌ 双线性性质不成立（因为使用哈希模拟，实际应用中应使用配对友好曲线）")

    print("\n[5] 实际应用说明:")
    print("这个实现使用SHA256模拟双线性配对，适用于演示但不适用于实际密码学应用")
    print("实际应用中应使用支持配对的椭圆曲线如BN254或BLS12-381")
    print("可使用py_ecc或petlib等库实现真实配对")


if __name__ == "__main__":
    demo_bilinear_group()