import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import hashlib


# 原始类定义（保持不变）
class BilinearGroup:
    """双线性群模拟器 (基于椭圆曲线)"""

    def __init__(self, curve=ec.SECP256R1):
        self.curve = curve
        self.backend = default_backend()

    def generate_group_params(self):
        """生成主密钥和公共参数"""
        private_key = ec.generate_private_key(self.curve(), self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def bilinear_map(self, P, Q):
        """模拟双线性映射 e(P, Q)"""
        # 实际实现应使用配对友好曲线，此为模拟
        combined = P.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        ) + Q.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return hashlib.sha256(combined).digest()


# 替换为实际模块名


class TestBilinearGroup(unittest.TestCase):
    def setUp(self):
        """创建测试所需的双线性群实例"""
        self.bilinear_group = BilinearGroup()

    def test_generate_group_params(self):
        """测试密钥对生成功能"""
        private_key, public_key = self.bilinear_group.generate_group_params()

        # 验证返回类型是否正确
        self.assertIsInstance(private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey)

        # 验证公钥是否与私钥匹配
        self.assertEqual(public_key.public_numbers(),
                         private_key.public_key().public_numbers())

    def test_bilinear_map_basic_functionality(self):
        """测试双线性映射的基本功能"""
        # 生成两组密钥对
        sk1, pk1 = self.bilinear_group.generate_group_params()
        sk2, pk2 = self.bilinear_group.generate_group_params()

        # 计算双线性映射结果
        result = self.bilinear_group.bilinear_map(pk1, pk2)

        # 验证输出类型和长度是否正确
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 32)  # SHA-256输出应为32字节

    def test_bilinear_map_consistency(self):
        """测试双线性映射的一致性（相同输入应产生相同输出）"""
        sk, pk = self.bilinear_group.generate_group_params()

        # 对相同输入计算两次
        result1 = self.bilinear_group.bilinear_map(pk, pk)
        result2 = self.bilinear_group.bilinear_map(pk, pk)

        # 验证结果是否一致
        self.assertEqual(result1, result2)

    def test_different_curves(self):
        """测试使用不同曲线时的功能"""
        # 尝试使用另一种曲线
        group_secp384 = BilinearGroup(curve=ec.SECP384R1)
        sk, pk = group_secp384.generate_group_params()

        # 验证生成的密钥属于指定曲线
        self.assertIsInstance(sk.curve, ec.SECP384R1)

        # 验证双线性映射仍能工作
        result = group_secp384.bilinear_map(pk, pk)
        self.assertEqual(len(result), 32)


if __name__ == '__main__':
    unittest.main()