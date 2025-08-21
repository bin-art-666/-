import random
from typing import Tuple, List, Dict


# 模拟双线性群环境
class BilinearGroup:
    def __init__(self, prime: int):
        self.p = prime  # 大素数阶
        self.g1 = random.randint(2, prime - 1)  # G1生成元
        self.g2 = random.randint(2, prime - 1)  # G2生成元
        self.gt = (self.g1 * self.g2) % prime  # GT生成元（模拟）

    def mult_g1(self, a: int, b: int) -> int:
        """G1群乘法 (a*b mod p)"""
        return (a * b) % self.p

    def pow_g1(self, a: int, exp: int) -> int:
        """G1群指数运算 (a^exp mod p)"""
        return pow(a, exp, self.p)

    def mult_g2(self, a: int, b: int) -> int:
        """G2群乘法"""
        return (a * b) % self.p

    def pow_g2(self, a: int, exp: int) -> int:
        """G2群指数运算"""
        return pow(a, exp, self.p)

    def bilinear_map(self, a: int, b: int) -> int:
        """双线性映射 e: G1×G2 → GT (模拟为a*b mod p)"""
        return (a * b) % self.p


# 功能加密方案 FE(k, Dₖ) 实现
class FE_Bilinear:
    def __init__(self, n: int, m: int, k: int, prime: int = 10 ** 9 + 7):
        self.n = n  # 向量维度
        self.m = m  # 向量维度
        self.k = k  # 矩阵分布参数
        self.bg = BilinearGroup(prime)  # 双线性群
        self.p = prime
        self.mpk, self.msk = self.setup()

    def setup(self) -> Tuple[Dict, Dict]:
        """生成公共参数和主密钥"""
        # 随机矩阵 A ∈ Zₚ^((k+1)×k), B ∈ Zₚ^((k+1)×k)
        A = [[random.randint(0, self.p - 1) for _ in range(self.k)] for __ in range(self.k + 1)]
        B = [[random.randint(0, self.p - 1) for _ in range(self.k)] for __ in range(self.k + 1)]

        # 随机向量 r_i, s_j (用于公共参数)
        r = [[random.randint(0, self.p - 1) for _ in range(self.k)] for __ in range(2 * self.n)]  # 2n个向量
        s = [[random.randint(0, self.p - 1) for _ in range(self.k)] for __ in range(2 * self.m)]  # 2m个向量

        # 计算公共参数中的群元素 [A r_i]_1 和 [B s_j]_2
        mpk = {
            "Ar": [self._matrix_vec_mul(A, ri, group=1) for ri in r],
            "Bs": [self._matrix_vec_mul(B, sj, group=2) for sj in s]
        }

        # 主密钥包含矩阵和随机向量
        msk = {"A": A, "B": B, "r": r, "s": s}
        return mpk, msk

    def keygen(self, F: List[List[int]]) -> Tuple[int, int]:
        """生成功能密钥 sk_F 对应矩阵 F"""
        A = self.msk["A"]
        B = self.msk["B"]
        r = self.msk["r"]
        s = self.msk["s"]

        # 计算密钥分量 K = Σ f_ij (r_i^T A^T B s_j + r_{n+i}^T A^T B s_{m+j})
        sum_k = 0
        for i in range(self.n):
            for j in range(self.m):
                f_ij = F[i][j]
                # 计算 r_i^T A^T B s_j
                term1 = self._vec_mat_vec(r[i], A, B, s[j])
                # 计算 r_{n+i}^T A^T B s_{m+j}
                term2 = self._vec_mat_vec(r[self.n + i], A, B, s[self.m + j])
                sum_k = (sum_k + f_ij * (term1 + term2)) % self.p

        # 随机化密钥
        u = random.randint(0, self.p - 1)
        K1 = self.bg.pow_g1(self.bg.g1, sum_k)
        K1 = self.bg.mult_g1(K1, self.bg.pow_g1(self.bg.g1, u))  # K1 = [sum_k + u]_1
        K2 = self.bg.pow_g2(self.bg.g2, u)  # K2 = [u]_2
        return (K1, K2)

    def encrypt(self, x: List[int], y: List[int]) -> Dict:
        """加密向量对 (x, y)"""
        # 生成随机参数
        gamma = random.randint(0, self.p - 1)
        sigma = random.randint(0, self.p - 1)
        W = self._random_invertible_matrix()  # 随机可逆矩阵 W ∈ GL_{k+2}

        # 加密分量 c_i = γ A r_i + γ x_i b^⊥ (模拟，实际需结合正交向量)
        c = []
        for i in range(self.n):
            ar = self.mpk["Ar"][i]
            c_i = self.bg.mult_g1(ar, self.bg.pow_g1(self.bg.g1, gamma))  # γ A r_i
            c_i = self.bg.mult_g1(c_i, self.bg.pow_g1(self.bg.g1, gamma * x[i]))  # + γ x_i b^⊥
            c.append(c_i)

        # 类似生成其他分量 (简化版)
        ct = {
            "c": c,
            "gamma_sigma": self.bg.pow_g2(self.bg.g2, gamma * sigma),
            "W": W
        }
        return ct

    def decrypt(self, ct: Dict, sk_F: Tuple[int, int]) -> int:
        """解密得到 x^T F y"""
        K1, K2 = sk_F
        c = ct["c"]
        gamma_sigma = ct["gamma_sigma"]

        # 计算双线性映射项 (简化版)
        term = self.bg.bilinear_map(K1, gamma_sigma)
        term = self.bg.bilinear_map(term, self.bg.pow_g2(self.bg.g2, -1))  # 去除随机化因子

        # 模拟最终结果 (实际需根据方案完整计算)
        return term

    # 辅助函数：矩阵-向量乘法并映射到对应群
    def _matrix_vec_mul(self, mat: List[List[int]], vec: List[int], group: int) -> int:
        res = 0
        for i in range(len(mat)):
            res += sum(mat[i][j] * vec[j] for j in range(len(vec)))
            res %= self.p
        return self.bg.pow_g1(self.bg.g1, res) if group == 1 else self.bg.pow_g2(self.bg.g2, res)

    # 辅助函数：计算 r^T A^T B s
    def _vec_mat_vec(self, r: List[int], A: List[List[int]], B: List[List[int]], s: List[int]) -> int:
        AT = list(zip(*A))  # A的转置
        BT = list(zip(*B))  # B的转置
        rAT = [sum(r[i] * AT[i][j] for i in range(len(r))) % self.p for j in range(len(AT[0]))]
        rATB = [sum(rAT[i] * B[i][j] for i in range(len(rAT))) % self.p for j in range(len(B[0]))]
        return sum(rATB[j] * s[j] for j in range(len(s))) % self.p

    # 生成随机可逆矩阵 (简化为单位矩阵)
    def _random_invertible_matrix(self) -> List[List[int]]:
        mat = [[0] * (self.k + 2) for _ in range(self.k + 2)]
        for i in range(self.k + 2):
            mat[i][i] = 1
        return mat


# 示例使用
if __name__ == "__main__":
    n, m, k = 2, 2, 3  # 向量维度和矩阵参数
    fe = FE_Bilinear(n, m, k)

    # 功能矩阵 F
    F = [[1, 2], [3, 4]]

    # 生成密钥
    sk_F = fe.keygen(F)

    # 加密向量 x, y
    x = [5, 6]
    y = [7, 8]
    ct = fe.encrypt(x, y)

    # 解密
    result = fe.decrypt(ct, sk_F)
    print(f"解密结果 (模拟值): {result}")
    print(f"预期 x^T F y = {5 * 1 * 7 + 5 * 2 * 8 + 6 * 3 * 7 + 6 * 4 * 8}")