import sys
import os

# 添加 pypbc 路径到 Python 路径
pypbc_path = os.path.expanduser("~/my_project/pypbc")
if pypbc_path not in sys.path:
    sys.path.insert(0, pypbc_path)

# 现在尝试导入 pypbc
try:
    from pypbc import *
    print("pypbc 导入成功")
except ImportError as e:
    print(f"pypbc 导入失败: {e}")

import numpy as np
import hashlib
import time
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple, List, Dict, Any
from pypbc import *



class BilinearGroup:
    def __init__(self):
        self.params = Parameters("type a")
        self.pairing = Pairing(self.params)
        self.g = Element.random(self.pairing, G1)          # 正确写法

    def generate_group_params(self):
        # 随机主密钥
        sk = Element.random(self.pairing, Zr)               # 注意这里
        pk = self.g ** sk
        return sk, pk, self.g

    def bilinear_map(self, P, Q):
        # 真正的双线性配对
        return self.pairing.apply(P, Q)

class QuadraticMIFE:
    """二次多输入函数加密（修正为论文III.C的qMIFE实现）"""

    def __init__(self, n_inputs: int, security_param: int = 128):
        self.n_inputs = n_inputs  # 输入槽数量（含标签）
        self.security_param = security_param
        self.group = BilinearGroup()
        self.msk, self.pp, self.generator = self.group.generate_group_params()  # 群生成元g
        self.ek = self._generate_encryption_keys()  # 每个输入槽的加密密钥

    def _generate_encryption_keys(self) -> Dict[int, Element]:
        """使用随机Oracle模型增强密钥生成"""
        ek = {}
        for i in range(self.n_inputs):
            # 使用随机Oracle模型从主密钥派生加密密钥
            h = hashlib.sha256()
            h.update(self.msk.__str__().encode())
            h.update(f"qMIFE_enc_key_{i}".encode())

            # 将哈希值映射到群ZR上
            ek_seed = int.from_bytes(h.digest(), 'big') % self.pairing.order()
            ek[i] = self.pairing.init(Zr, ek_seed)

        return ek

    def encrypt(self, input_index: int, x: np.ndarray) -> List[Element]:
        """改进的加密实现，返回群元素列表"""
        assert input_index < self.n_inputs, "输入槽索引无效"

        # 使用真正的椭圆曲线点加密
        priv_key = self.ek[input_index]  # 应该是群ZR中的元素
        ct_list = []

        for val in x:
            # 将值映射到群上并加密
            val_element = self.pairing.init(Zr, int(val * 1000))  # 适当缩放
            ct_element = self.g ** (priv_key * val_element)
            ct_list.append(ct_element)

        return ct_list

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

    def decrypt(self, ciphertexts: List[List[Element]], sk: Element, c: np.ndarray) -> float:
        """改进的解密实现，计算⟨c, x⊗x⟩"""
        # 这里需要实现真正的二次函数解密逻辑
        # 根据论文中的构造计算双线性配对组合
        result = self.pairing.init(GT, 1)

        # 实现论文中的解密算法
        for i in range(len(ciphertexts)):
            for j in range(len(ciphertexts)):
                if abs(c[i * len(ciphertexts) + j]) > 1e-10:  # 非零系数
                    # 计算 e(CT_i, CT_j) 的 c[i,j] 次方
                    pairing_result = self.bilinear_map(ciphertexts[i], ciphertexts[j])
                    result *= pairing_result ** (c[i * len(ciphertexts) + j])

        # 将结果映射回实数
        return self.map_from_group(result)

    def encrypt_with_proof(self, input_index: int, x: np.ndarray) -> Tuple[List[Element], List[Element]]:
        """添加零知识证明的加密，防止恶意行为"""
        ciphertexts = self.encrypt(input_index, x)

        # 生成证明（简化示例）
        proofs = []
        for ct in ciphertexts:
            # 生成证明 ciphertext 是正确形成的
            r = self.pairing.random(Zr)
            proof = (self.g ** r, ct ** r)  # 简化的Sigma协议
            proofs.append(proof)

        return ciphertexts, proofs

    def verify_encryption(self, input_index: int, ciphertexts: List[Element],
                          proofs: List[Tuple[Element, Element]]) -> bool:
        """验证加密的正确性"""
        for i, (ct, (a, b)) in enumerate(zip(ciphertexts, proofs)):
            # 验证证明（简化示例）
            left = self.bilinear_map(a, self.ek[input_index] * self.g)
            right = self.bilinear_map(b, self.g)

            if left != right:
                return False

        return True

    def precompute_pairings(self, base_elements: List[Element]) -> Dict[Tuple[int, int], Element]:
        """预计算配对结果以提高解密性能"""
        precomputed = {}
        n = len(base_elements)

        for i in range(n):
            for j in range(i, n):  # 利用对称性减少计算量
                precomputed[(i, j)] = self.bilinear_map(base_elements[i], base_elements[j])
                if i != j:
                    precomputed[(j, i)] = precomputed[(i, j)]  # 对称性

        return precomputed

    def decrypt_fast(self, ciphertexts: List[Element], sk: Element, c: np.ndarray,
                     precomputed: Dict[Tuple[int, int], Element]) -> float:
        """使用预计算结果的快速解密"""
        result = self.pairing.init(GT, 1)
        n = len(ciphertexts)

        for i in range(n):
            for j in range(n):
                coef = c[i * n + j]
                if abs(coef) > 1e-10:
                    result *= precomputed[(i, j)] ** coef

        return self.map_from_group(result)


def test_basic_functionality():
    """测试基本功能"""
    print("开始基本功能测试...")

    try:
        # 创建 qMIFE 实例
        qmife = QuadraticMIFE(n_inputs=2)
        print("✓ QuadraticMIFE 初始化成功")

        # 测试数据
        x = np.array([1.0, 2.0])
        print(f"测试数据: {x}")

        # 加密
        ct1 = qmife.encrypt(0, np.array([x[0]]))
        ct2 = qmife.encrypt(1, np.array([x[1]]))
        print("✓ 加密成功")
        print(f"密文 1 长度: {len(ct1)}")
        print(f"密文 2 长度: {len(ct2)}")

        # 生成函数密钥（需要先实现map_from_group才能测试解密）
        c = np.array([1.0, 0.0, 0.0, 1.0])  # x₁² + x₂²
        sk = qmife.keygen(c)
        print("✓ 密钥生成成功")
        print(f"密钥长度: {len(sk)} 字节")

        return True
    except Exception as e:
        print(f"✗ 基本功能测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_encryption_performance():
    """测试加密性能"""
    print("\n开始加密性能测试...")

    sizes = [2, 5, 10]  # 输入规模
    encryption_times = []

    for size in sizes:
        try:
            qmife = QuadraticMIFE(n_inputs=size)

            # 测试数据
            x = np.random.rand(size)

            # 测量加密时间
            start_time = time.time()
            ciphertexts = []
            for i in range(size):
                ct = qmife.encrypt(i, np.array([x[i]]))
                ciphertexts.append(ct)
            end_time = time.time()

            elapsed = end_time - start_time
            encryption_times.append(elapsed)
            print(f"规模 {size}: {elapsed:.4f}秒, 平均每加密: {elapsed / size:.4f}秒")

        except Exception as e:
            print(f"规模 {size} 测试失败: {e}")
            encryption_times.append(float('nan'))

    return sizes, encryption_times


def test_memory_usage():
    """测试内存使用情况"""
    print("\n开始内存使用测试...")

    # 使用 memory_profiler 来测量内存使用
    try:
        from memory_profiler import memory_usage
        mem_usage = memory_usage((test_memory_single, (5,)))
        print(f"内存使用峰值: {max(mem_usage):.2f} MiB")
        return max(mem_usage)
    except ImportError:
        print("未安装 memory_profiler，跳过内存测试")
        return None


def test_memory_single(n_inputs):
    """用于内存测试的辅助函数"""
    qmife = QuadraticMIFE(n_inputs=n_inputs)
    x = np.random.rand(n_inputs)
    ciphertexts = []
    for i in range(n_inputs):
        ct = qmife.encrypt(i, np.array([x[i]]))
        ciphertexts.append(ct)
    return ciphertexts


def test_scalability():
    """测试算法可扩展性"""
    print("\n测试算法可扩展性...")

    # 测试不同安全参数下的性能
    security_params = [80, 112, 128]
    times_by_security = []

    for param in security_params:
        try:
            start_time = time.time()
            qmife = QuadraticMIFE(n_inputs=5, security_param=param)
            end_time = time.time()

            elapsed = end_time - start_time
            times_by_security.append(elapsed)
            print(f"安全参数 {param}: {elapsed:.4f}秒")

        except Exception as e:
            print(f"安全参数 {param} 测试失败: {e}")
            times_by_security.append(float('nan'))

    return security_params, times_by_security


def plot_performance(sizes, encryption_times, security_params, security_times):
    """绘制性能图表"""
    plt.figure(figsize=(12, 5))

    # 子图1: 加密性能 vs 输入规模
    plt.subplot(1, 2, 1)
    plt.plot(sizes, encryption_times, 'o-', linewidth=2, markersize=8)
    plt.xlabel('输入规模')
    plt.ylabel('加密时间 (秒)')
    plt.title('加密性能 vs 输入规模')
    plt.grid(True, linestyle='--', alpha=0.7)

    # 子图2: 初始化时间 vs 安全参数
    plt.subplot(1, 2, 2)
    plt.plot(security_params, security_times, 's-', linewidth=2, markersize=8)
    plt.xlabel('安全参数')
    plt.ylabel('初始化时间 (秒)')
    plt.title('初始化时间 vs 安全参数')
    plt.grid(True, linestyle='--', alpha=0.7)

    plt.tight_layout()
    plt.savefig('performance_analysis.png', dpi=300, bbox_inches='tight')
    plt.show()


def run_comprehensive_tests():
    """运行全面测试"""
    print("=" * 60)
    print("开始全面测试 Quadratic MIFE 实现")
    print("=" * 60)

    # 运行基本功能测试
    basic_test_passed = test_basic_functionality()

    # 运行加密性能测试
    sizes, encryption_times = test_encryption_performance()

    # 运行内存使用测试
    mem_usage = test_memory_usage()

    # 运行可扩展性测试
    security_params, security_times = test_scalability()

    # 绘制性能图表
    plot_performance(sizes, encryption_times, security_params, security_times)

    # 输出测试总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    print(f"基本功能测试: {'通过' if basic_test_passed else '失败'}")
    print(f"加密性能: {encryption_times}")
    if mem_usage:
        print(f"内存使用峰值: {mem_usage:.2f} MiB")
    print(f"安全参数影响: {security_times}")
    print("性能图表已保存为 'performance_analysis.png'")


if __name__ == "__main__":
    run_comprehensive_tests()

