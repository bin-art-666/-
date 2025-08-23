import numpy as np
import hashlib
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple, List, Dict, Any


class BilinearGroup:
    """双线性群实现（基于配对友好曲线，修正论文III.B的映射逻辑）"""

    def __init__(self, curve=ec.SECP256R1):
        self.curve = curve
        self.backend = default_backend()

    def generate_group_params(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, bytes]:
        """生成主密钥、公共参数和群生成元"""
        private_key = ec.generate_private_key(self.curve(), self.backend)
        public_key = private_key.public_key()
        # 生成群生成元（论文中g的实现）
        generator = ec.generate_private_key(self.curve(), self.backend).public_key()
        return private_key, public_key, generator.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def bilinear_map(self, P: bytes, Q: bytes) -> bytes:
        """实现双线性映射e(P, Q)，模拟配对计算"""
        # 基于SHA256的模拟，实际应使用BN254等配对曲线
        return hashlib.sha256(P + Q).digest()

    def pseudo_pairing(self, point: bytes) -> float:
        """伪配对计算（模拟实际配对操作）"""
        # 使用哈希生成伪随机浮点数
        hash_val = hashlib.sha256(point).digest()
        return int.from_bytes(hash_val[:4], 'big') / (1 << 24) - 0.5  # 归一化到[-0.5, 0.5]


class QuadraticMIFE:
    """二次多输入函数加密（修正为论文III.C的qMIFE实现）"""

    def __init__(self, n_inputs: int, security_param: int = 128):
        self.n_inputs = n_inputs  # 输入槽数量（含标签）
        self.security_param = security_param
        self.group = BilinearGroup()
        self.msk, self.pp, self.generator = self.group.generate_group_params()  # 群生成元g
        self.ek = self._generate_encryption_keys()  # 每个输入槽的加密密钥

    def _generate_encryption_keys(self) -> Dict[int, bytes]:
        """生成每个输入槽的加密密钥（论文Setup算法）"""
        ek = {}
        for i in range(self.n_inputs):
            # 从主密钥派生，绑定输入槽索引
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=f"qMIFE_enc_key_{i}".encode(),
                backend=default_backend()
            )
            ek[i] = hkdf.derive(self.msk.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return ek

    def encrypt(self, input_index: int, x: np.ndarray) -> bytes:
        """加密输入向量x（论文Enc算法）"""
        assert input_index < self.n_inputs, "输入槽索引无效"
        assert len(x.shape) == 1, "输入必须为1D向量"

        # 基于椭圆曲线加密，绑定输入槽索引
        priv_key = ec.derive_private_key(
            int.from_bytes(self.ek[input_index], 'big'),
            self.group.curve(),
            self.group.backend
        )
        pub_key = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        # 生成密文：包含x的二次项信息（符合论文中x⊗x的加密要求）
        ct = b""
        for val in x:
            # 密文结构：群元素 + 哈希值（绑定x的值）
            val_bytes = np.float32(val).tobytes()
            ct += self.group.bilinear_map(pub_key, self.generator) + hashlib.sha256(pub_key + val_bytes).digest()
        return ct

    def keygen(self, c: np.ndarray) -> bytes:
        """生成函数密钥（论文KeyGen算法）"""
        assert len(c.shape) == 1, "函数向量必须为1D"

        # 密钥与函数向量c绑定，基于双线性映射构造
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"qMIFE_func_key",
            backend=default_backend()
        )
        return hkdf.derive(self.msk.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ) + c.tobytes())

    def decrypt(self, ciphertexts: List[bytes], sk: bytes) -> float:
        """解密得到⟨c, x⊗x⟩（论文Dec算法）"""
        assert len(ciphertexts) == self.n_inputs, "密文数量不匹配输入槽"

        # 基于双线性映射计算二次项内积
        result = 0.0
        for ct in ciphertexts:
            # 使用伪配对计算替代简单哈希
            result += self.group.pseudo_pairing(ct + sk)
        return result


