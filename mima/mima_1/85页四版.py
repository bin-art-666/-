import numpy as np
import random
from typing import Tuple, List


class VirtualBilinearGroup:
    """
    模拟的双线性群环境，用于学术演示
    注意：这不提供真正的密码学安全性
    """

    def __init__(self, security_param: int = 128):
        # 生成一个足够大的素数p
        self.p = self.generate_prime(security_param)
        self.G1 = self.ModGroup(self.p, "G1")
        self.G2 = self.ModGroup(self.p, "G2")
        self.GT = self.ModGroup(self.p, "GT")

        # 生成元
        self.g1 = self.G1(1)  # g1生成元
        self.g2 = self.G2(1)  # g2生成元
        self.gT = self.GT(1)  # gT生成元

    def generate_prime(self, bits: int) -> int:
        """生成一个足够大的素数"""
        # 这里使用一个较小的素数用于演示
        # 在实际应用中应该使用密码学安全的素数生成方法
        return 1000003  # 示例素数

    class ModGroup:
        """模拟素数阶群"""

        def __init__(self, p: int, name: str):
            self.p = p
            self.name = name

        def __call__(self, exponent: int):
            """创建群元素"""
            return self.Element(exponent % self.p, self)

        class Element:
            """群元素类"""

            def __init__(self, value: int, group):
                self.value = value
                self.group = group

            def __add__(self, other):
                """群运算（加法表示法）"""
                if isinstance(other, int):
                    return self.group((self.value + other) % self.group.p)
                return self.group((self.value + other.value) % self.group.p)

            def __mul__(self, other):
                """标量乘法"""
                if isinstance(other, int):
                    return self.group((self.value * other) % self.group.p)
                raise ValueError("只能与整数相乘")

            def __sub__(self, other):
                """群减法"""
                if isinstance(other, int):
                    return self.group((self.value - other) % self.group.p)
                return self.group((self.value - other.value) % self.group.p)

            def __eq__(self, other):
                """相等比较"""
                return self.value == other.value and self.group == other.group

            def __str__(self):
                return f"[{self.value}]_{self.group.name}"

            def __repr__(self):
                return str(self)

    def pair(self, g1_elem, g2_elem):
        """模拟双线性配对 e: G1 × G2 → GT"""
        if not (isinstance(g1_elem, self.ModGroup.Element) and
                isinstance(g2_elem, self.ModGroup.Element)):
            raise ValueError("输入必须是群元素")

        # 在真实双线性群中，e(g1^a, g2^b) = gT^(a*b)
        # 这里我们模拟这个性质
        a = g1_elem.value
        b = g2_elem.value
        return self.GT((a * b) % self.p)


class FEGGM:
    """
    论文第4节的功能性加密方案FE_GGM实现
    """

    def __init__(self, n: int, security_param: int = 128):
        """
        初始化

        参数:
            n: 向量维度
            security_param: 安全参数
        """
        self.n = n
        self.bgp = VirtualBilinearGroup(security_param)
        self.p = self.bgp.p

    def setup(self):
        """
        设置算法

        返回:
            mpk: 主公钥
            msk: 主私钥
        """
        # 随机选择w, a, b
        w = random.randint(0, self.p - 1)
        a = np.array([random.randint(0, self.p - 1) for _ in range(self.n)])
        b = np.array([random.randint(0, self.p - 1) for _ in range(self.n)])

        # 转换为群元素
        a_g1 = [self.bgp.G1(ai) for ai in a]
        b_g2 = [self.bgp.G2(bi) for bi in b]
        w_g2 = self.bgp.G2(w)

        # 主私钥和主公钥
        msk = (w, a, b)
        mpk = (self.bgp, a_g1, b_g2, w_g2)

        return mpk, msk

    def keygen(self, msk, F):
        """
        密钥生成算法

        参数:
            msk: 主私钥
            F: n×n矩阵

        返回:
            skF: 功能密钥
        """
        w, a, b = msk

        # 计算a^T F b
        aT_F = np.dot(a, F)  # a^T F
        aT_F_b = np.dot(aT_F, b) % self.p  # (a^T F) b

        # 随机选择γ
        gamma = random.randint(0, self.p - 1)

        # 计算S1和S2
        S1_val = (aT_F_b + gamma * w) % self.p
        S2_val = gamma

        # 转换为群元素
        S1 = self.bgp.G1(S1_val)
        S2 = self.bgp.G1(S2_val)

        return (S1, S2, F)

    def encrypt(self, mpk, x, y):
        """
        加密算法

        参数:
            mpk: 主公钥
            x, y: 要加密的向量

        返回:
            Ct: 密文
        """
        bgp, a_g1, b_g2, w_g2 = mpk

        # 生成随机数
        r = random.randint(0, self.p - 1)
        s = random.randint(0, self.p - 1)
        t = random.randint(0, self.p - 1)
        z = random.randint(0, self.p - 1)

        # 计算c = [r·a + x]_1
        c = [bgp.G1((r * a_g1[i].value + x[i]) % self.p) for i in range(self.n)]

        # 计算d = [s·b + y]_2
        d = [bgp.G2((s * b_g2[i].value + y[i]) % self.p) for i in range(self.n)]

        # 计算c_tilde = [t·a + s·x]_1
        c_tilde = [bgp.G1((t * a_g1[i].value + s * x[i]) % self.p) for i in range(self.n)]

        # 计算d_tilde = [z·b + r·y]_2
        d_tilde = [bgp.G2((z * b_g2[i].value + r * y[i]) % self.p) for i in range(self.n)]

        # 计算E = [rs - z - t]_2
        E_val = (r * s - z - t) % self.p
        E = bgp.G2(E_val)

        # 计算E_tilde = [w(rs - z - t)]_2
        E_tilde_val = (w_g2.value * E_val) % self.p
        E_tilde = bgp.G2(E_tilde_val)

        return (c, c_tilde, d, d_tilde, E, E_tilde)

    def decrypt(self, mpk, skF, Ct):
        """
        解密算法

        参数:
            mpk: 主公钥
            skF: 功能密钥
            Ct: 密文

        返回:
            result: 解密结果[x^T F y]_T
        """
        bgp, a_g1, b_g2, w_g2 = mpk
        S1, S2, F = skF
        c, c_tilde, d, d_tilde, E, E_tilde = Ct

        # 计算c^T F d
        term1 = bgp.GT(0)  # 初始化为GT中的零元素
        for i in range(self.n):
            for j in range(self.n):
                # c_i * F_{i,j} * d_j
                product = (c[i].value * F[i, j] * d[j].value) % self.p
                term1 = term1 + bgp.GT(product)

        # 计算[a]_1^T F d_tilde
        term2 = bgp.GT(0)
        for i in range(self.n):
            for j in range(self.n):
                # a_i * F_{i,j} * d_tilde_j
                product = (a_g1[i].value * F[i, j] * d_tilde[j].value) % self.p
                term2 = term2 + bgp.GT(product)

        # 计算c_tilde^T F [b]_2
        term3 = bgp.GT(0)
        for i in range(self.n):
            for j in range(self.n):
                # c_tilde_i * F_{i,j} * b_j
                product = (c_tilde[i].value * F[i, j] * b_g2[j].value) % self.p
                term3 = term3 + bgp.GT(product)

        # 计算e(S1, E)
        term4 = bgp.pair(S1, E)

        # 计算e(S2, E_tilde)
        term5 = bgp.pair(S2, E_tilde)

        # 计算最终结果
        result = term1 - term2 - term3 - term4 + term5

        return result


# 测试代码
def test_fe_ggm():
    """测试FE_GGM方案"""
    print("测试FE_GGM方案...")

    # 设置参数
    n = 2  # 向量维度
    fe = FEGGM(n)

    # 生成主公钥和主私钥
    mpk, msk = fe.setup()
    print("设置完成")

    # 定义功能矩阵F
    F = np.array([[1, 2], [3, 4]])  # 2x2矩阵

    # 生成功能密钥
    skF = fe.keygen(msk, F)
    print("功能密钥生成完成")

    # 定义要加密的向量
    x = np.array([1, 2])
    y = np.array([3, 4])

    # 加密
    Ct = fe.encrypt(mpk, x, y)
    print("加密完成")

    # 解密
    result = fe.decrypt(mpk, skF, Ct)
    print(f"解密结果: {result}")

    # 验证正确性：计算x^T F y
    expected = np.dot(x, np.dot(F, y)) % fe.p
    print(f"预期结果: [{expected}]_GT")

    # 检查结果是否正确
    if result.value == expected:
        print("✓ 解密结果正确")
    else:
        print("✗ 解密结果错误")

    return result.value == expected


if __name__ == "__main__":
    test_fe_ggm()