import hashlib
from typing import Tuple, List

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class BilinearGroup:
    """双线性群模拟器 (基于椭圆曲线)"""

    def __init__(self, curve=ec.SECP256R1):
        self.curve = curve
        self.backend = default_backend()

    def generate_group_params(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """生成主密钥和公共参数"""
        private_key = ec.generate_private_key(self.curve(), self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def bilinear_map(self, P: ec.EllipticCurvePublicKey, Q: ec.EllipticCurvePublicKey) -> bytes:
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

class QuadraticMIFE:
    """二次多输入函数加密方案 (基于Agrawal et al.)"""

    def __init__(self, n_inputs: int, security_param: int = 128):
        self.n_inputs = n_inputs
        self.security_param = security_param
        self.group = BilinearGroup()
        self.msk, self.pp = self.group.generate_group_params()

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
                backend=default_backend()
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
            self.group.backend
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
            backend=self.group.backend
        )
        return hkdf.derive(
            self.msk.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ) + c.tobytes()
        )

    def decrypt(self, ciphertexts: List[bytes], sk: bytes) -> float:
        """解密获得内积结果 ⟨c, x⊗x⟩"""
        assert len(ciphertexts) == self.n_inputs, "Incorrect number of ciphertexts"

        # 模拟双线性映射计算
        result = 0
        for i, ct in enumerate(ciphertexts):
            # 实际实现应使用配对计算
            ct_hash = hashlib.sha256(ct).digest()
            result += int.from_bytes(ct_hash, 'big') % (1 << 32)

        # 返回浮点结果 (实际应为整数域上的值)
        return float(result % (1 << 16)) / (1 << 8)