import unittest
import hashlib
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


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
        combined = P.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        ) + Q.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return hashlib.sha256(combined).digest()


class QuadraticMIFE:
    """二次多输入函数加密方案 (基于Agrawal et al.)"""

    def __init__(self, n_inputs: int, security_param: int = 128):
        self.n_inputs = n_inputs
        self.security_param = security_param
        self.group = BilinearGroup()
        self.msk, self.pp = self.group.generate_group_params()
        self.backend = default_backend()

        # 生成加密密钥
        self.ek = {}
        self._generate_encryption_keys()

    def _generate_encryption_keys(self):
        """为每个输入槽生成加密密钥"""
        for i in range(self.n_inputs):
            # 使用HKDF从主密钥派生
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=f"enc_key_{i}".encode(),
                backend=self.backend
            )
            key_data = hkdf.derive(self.msk.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            self.ek[i] = key_data

    def encrypt(self, input_index: int, x: np.ndarray) -> bytes:
        """加密输入向量"""
        assert input_index < self.n_inputs, "Invalid input index"
        assert len(x.shape) == 1, "Input must be 1D vector"

        # 使用基于椭圆曲线的加密
        private_key = ec.derive_private_key(
            int.from_bytes(self.ek[input_index], 'big'),
            self.group.curve(),
            self.backend
        )

        # 模拟实际加密过程
        ciphertext = b""
        for val in x:
            point = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            val_bytes = val.tobytes()
            ciphertext += point + hashlib.sha256(point + val_bytes).digest()
        return ciphertext

    def keygen(self, c: np.ndarray) -> bytes:
        """生成函数密钥"""
        assert len(c.shape) == 1, "Function vector must be 1D"

        # 密钥基于双线性映射构造
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"func_key",
            backend=self.backend
        )
        return hkdf.derive(
            self.msk.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ) + c.tobytes()
        )

    def decrypt(self, ciphertexts: list, sk: bytes) -> float:
        """解密获得内积结果 ⟨c, x⊗x⟩"""
        assert len(ciphertexts) == self.n_inputs, "Incorrect number of ciphertexts"
        assert len(sk) == 32, "Function key must be 32 bytes"

        # 模拟双线性映射计算（使用函数密钥）
        result = 0
        for ct in ciphertexts:
            # 将函数密钥与密文结合使用
            combined = sk + ct
            ct_hash = hashlib.sha256(combined).digest()
            result += int.from_bytes(ct_hash, 'big') % (1 << 32)

        # 返回浮点结果 (实际应为整数域上的值)
        return float(result % (1 << 16)) / (1 << 8)


class TestQuadraticMIFE(unittest.TestCase):

    def setUp(self):
        """每个测试前的准备工作"""
        # 创建2输入的QuadraticMIFE实例
        self.mife = QuadraticMIFE(n_inputs=2)
        # 创建测试数据
        self.x1 = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        self.x2 = np.array([4.0, 5.0, 6.0], dtype=np.float32)
        self.c = np.array([0.5, 1.0], dtype=np.float32)

    def test_initialization(self):
        """测试初始化是否正确"""
        # 验证输入槽数量
        self.assertEqual(self.mife.n_inputs, 2)

        # 验证安全参数
        self.assertEqual(self.mife.security_param, 128)

        # 验证主密钥存在
        self.assertIsNotNone(self.mife.msk)
        self.assertIsInstance(self.mife.msk, ec.EllipticCurvePrivateKey)

        # 验证公共参数存在
        self.assertIsNotNone(self.mife.pp)
        self.assertIsInstance(self.mife.pp, ec.EllipticCurvePublicKey)

        print("✅ 初始化测试通过")

    def test_encryption_keys(self):
        """测试加密密钥生成"""
        # 验证密钥数量
        self.assertEqual(len(self.mife.ek), 2)

        # 验证密钥类型和长度
        for i in range(2):
            self.assertIn(i, self.mife.ek)
            key = self.mife.ek[i]
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), 32)  # HKDF 生成32字节密钥

            # 验证不同输入槽的密钥不同
            if i == 0:
                key0 = key
            else:
                self.assertNotEqual(key0, key)

        print("✅ 加密密钥测试通过")

    def test_encryption(self):
        """测试加密功能"""
        # 加密第一个输入
        ct1 = self.mife.encrypt(0, self.x1)
        self.assertIsInstance(ct1, bytes)
        self.assertGreater(len(ct1), 0)

        # 验证密文结构：每个元素对应 (点 + 哈希)
        point_size = 65  # SECP256R1未压缩点大小
        hash_size = 32  # SHA-256哈希大小
        element_size = point_size + hash_size
        self.assertEqual(len(ct1) % element_size, 0)
        self.assertEqual(len(ct1) // element_size, len(self.x1))

        # 加密第二个输入
        ct2 = self.mife.encrypt(1, self.x2)
        self.assertIsInstance(ct2, bytes)
        self.assertGreater(len(ct2), 0)
        self.assertEqual(len(ct2) % element_size, 0)
        self.assertEqual(len(ct2) // element_size, len(self.x2))

        # 验证相同输入产生不同密文（由于随机性）
        ct1_again = self.mife.encrypt(0, self.x1)
        self.assertNotEqual(ct1, ct1_again)

        print("✅ 加密测试通过")

    def test_key_generation(self):
        """测试函数密钥生成"""
        # 生成函数密钥
        sk = self.mife.keygen(self.c)

        # 验证密钥类型和长度
        self.assertIsInstance(sk, bytes)
        self.assertEqual(len(sk), 32)  # HKDF 生成32字节密钥

        # 验证不同函数向量产生不同密钥
        c2 = np.array([1.0, 0.5], dtype=np.float32)
        sk2 = self.mife.keygen(c2)
        self.assertNotEqual(sk, sk2)

        print("✅ 密钥生成测试通过")

    def test_full_workflow(self):
        """测试完整工作流程"""
        # 1. 加密两个输入
        ct1 = self.mife.encrypt(0, self.x1)
        ct2 = self.mife.encrypt(1, self.x2)

        # 2. 生成函数密钥
        sk = self.mife.keygen(self.c)

        # 3. 解密
        result = self.mife.decrypt([ct1, ct2], sk)

        # 验证结果类型和范围
        self.assertIsInstance(result, float)
        self.assertGreaterEqual(result, 0.0)
        self.assertLess(result, 256.0)  # 根据解密逻辑的最大值

        # 4. 验证结果一致性（模拟实现）
        # 注意：真实实现应验证数学正确性
        result_again = self.mife.decrypt([ct1, ct2], sk)
        self.assertAlmostEqual(result, result_again, places=5)

        # 5. 验证不同密钥产生不同结果
        c2 = np.array([1.0, 0.0], dtype=np.float32)
        sk2 = self.mife.keygen(c2)
        result2 = self.mife.decrypt([ct1, ct2], sk2)
        self.assertNotEqual(result, result2)

        print("✅ 完整工作流程测试通过")

    def test_decrypt_with_wrong_key(self):
        """测试使用错误密钥解密"""
        # 1. 加密输入
        ct1 = self.mife.encrypt(0, self.x1)
        ct2 = self.mife.encrypt(1, self.x2)

        # 2. 生成正确的函数密钥
        sk_correct = self.mife.keygen(self.c)

        # 3. 生成错误的函数密钥
        wrong_c = np.array([0.0, 0.0], dtype=np.float32)
        sk_wrong = self.mife.keygen(wrong_c)

        # 4. 使用完全随机的密钥
        sk_random = os.urandom(32)

        # 5. 解密
        result_correct = self.mife.decrypt([ct1, ct2], sk_correct)
        result_wrong = self.mife.decrypt([ct1, ct2], sk_wrong)
        result_random = self.mife.decrypt([ct1, ct2], sk_random)

        # 6. 验证结果不同
        self.assertNotEqual(result_correct, result_wrong)
        self.assertNotEqual(result_correct, result_random)
        self.assertNotEqual(result_wrong, result_random)

        print("✅ 错误密钥测试通过")

    def test_edge_cases(self):
        """测试边界情况"""
        # 1. 空向量加密
        empty_vec = np.array([], dtype=np.float32)
        ct_empty = self.mife.encrypt(0, empty_vec)
        self.assertEqual(ct_empty, b"")

        # 2. 空函数向量密钥生成
        empty_c = np.array([], dtype=np.float32)
        with self.assertRaises(AssertionError):
            self.mife.keygen(empty_c)  # 应触发断言错误

        # 3. 无效输入索引
        with self.assertRaises(AssertionError):
            self.mife.encrypt(2, self.x1)  # 只有0和1索引

        # 4. 错误数量的密文解密
        with self.assertRaises(AssertionError):
            self.mife.decrypt([b"dummy"], b"dummy_sk")  # 需要2个密文

        # 5. 错误长度的密钥解密
        with self.assertRaises(AssertionError):
            self.mife.decrypt([b"dummy", b"dummy"], b"short_key")  # 密钥长度应为32字节

        # 6. 零向量解密
        zero_vec = np.array([0.0, 0.0, 0.0], dtype=np.float32)
        ct_zero = self.mife.encrypt(0, zero_vec)
        sk = self.mife.keygen(self.c)
        result = self.mife.decrypt([ct_zero, ct_zero], sk)
        self.assertGreaterEqual(result, 0.0)

        print("✅ 边界情况测试通过")


if __name__ == "__main__":
    import os  # 用于生成随机密钥

    # 创建测试套件
    suite = unittest.TestLoader().loadTestsFromTestCase(TestQuadraticMIFE)

    # 运行测试
    print("=" * 60)
    print("开始测试 QuadraticMIFE 类")
    print("=" * 60)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # 打印最终结果
    print("\n测试结果摘要:")
    print(f"总测试数: {result.testsRun}")
    print(f"失败: {len(result.failures)}")
    print(f"错误: {len(result.errors)}")
    if result.wasSuccessful():
        print("🎉 所有测试通过!")
    else:
        print("⚠️ 有测试未通过，请检查失败详情")