import random
import math
from typing import List, Tuple, Dict, Any


class DDHFunctionalEncryption:
    def __init__(self, security_param: int = 1024):
        """
        初始化DDH功能加密方案
        :param security_param: 安全参数，用于生成大素数
        """
        self.security_param = security_param
        self.G, self.q, self.g, self.h = self._generate_group(security_param)
        self.l = None  # 向量维度将在Setup时确定

    def _generate_group(self, bit_length: int) -> Tuple[Dict[str, Any], int, int, int]:
        """
        生成循环群G
        :param bit_length: 素数的比特长度
        :return: (群G, 群的阶q, 生成元g, 生成元h)
        """
        # 生成安全素数 q = 2p + 1，其中p也是素数
        q = self._generate_safe_prime(bit_length)
        p = (q - 1) // 2

        # 在Z_q*中找生成元g
        g = self._find_generator(q)
        h = self._find_generator(q)  # 另一个生成元

        group = {
            'q': q,
            'p': p,
            'bit_length': bit_length
        }
        return group, q, g, h

    def _generate_safe_prime(self, bit_length: int) -> int:
        """生成安全素数 q = 2p + 1，其中p也是素数"""
        while True:
            p = random.getrandbits(bit_length - 1)
            p |= (1 << (bit_length - 2))  # 确保是奇数
            if self._is_prime(p) and self._is_prime(2 * p + 1):
                return 2 * p + 1

    def _is_prime(self, n: int, k: int = 10) -> bool:
        """Miller-Rabin素性测试"""
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # 写成 n-1 = 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # 测试k个基
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _find_generator(self, q: int) -> int:
        """寻找循环群Z_q*的生成元"""
        p = (q - 1) // 2  # 因为q是安全素数，q-1=2p
        factors = [2, p]

        while True:
            g = random.randint(2, q - 1)
            is_gen = True
            for factor in factors:
                if pow(g, (q - 1) // factor, q) == 1:
                    is_gen = False
                    break
            if is_gen:
                return g

    def setup(self, l: int) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        系统初始化
        :param l: 向量维度
        :return: (公钥mpk, 主密钥msk)
        """
        self.l = l
        msk = {
            's': [random.randint(0, self.q - 1) for _ in range(l)],
            't': [random.randint(0, self.q - 1) for _ in range(l)]
        }

        h_list = []
        for i in range(l):
            h_i = (pow(self.g, msk['s'][i], self.q) *
                   pow(self.h, msk['t'][i], self.q)) % self.q
            h_list.append(h_i)

        mpk = {
            'G': self.G,
            'g': self.g,
            'h': self.h,
            'h_list': h_list,
            'q': self.q,
            'l': l
        }

        return mpk, msk

    def keygen(self, msk: Dict[str, Any], x: List[int]) -> Dict[str, int]:
        """
        生成密钥
        :param msk: 主密钥
        :param x: 向量x
        :return: 密钥sk_x
        """
        if len(x) != self.l:
            raise ValueError(f"向量维度必须为{self.l}")

        s_x = sum(msk['s'][i] * x[i] for i in range(self.l)) % self.q
        t_x = sum(msk['t'][i] * x[i] for i in range(self.l)) % self.q

        return {
            's_x': s_x,
            't_x': t_x
        }

    def encrypt(self, mpk: Dict[str, Any], y: List[int]) -> Dict[str, Any]:
        """
        加密向量y
        :param mpk: 公钥
        :param y: 向量y
        :return: 密文
        """
        if len(y) != mpk['l']:
            raise ValueError(f"向量维度必须为{mpk['l']}")

        q = mpk['q']
        r = random.randint(0, q - 1)

        C = pow(mpk['g'], r, q)
        D = pow(mpk['h'], r, q)

        E = []
        for i in range(mpk['l']):
            e_i = (pow(mpk['g'], y[i], q) *
                   pow(mpk['h_list'][i], r, q)) % q
            E.append(e_i)

        return {
            'C': C,
            'D': D,
            'E': E
        }

    def decrypt(self, mpk: Dict[str, Any], sk_x: Dict[str, int], ct: Dict[str, Any]) -> int:
        """
        解密获取内积<x, y>
        :param mpk: 公钥
        :param sk_x: 密钥
        :param ct: 密文
        :return: 内积结果
        """
        q = mpk['q']
        l = mpk['l']

        # 计算E_x = product(E_i^x_i) / (C^s_x * D^t_x) mod q
        numerator = 1
        for i in range(l):
            numerator = (numerator * pow(ct['E'][i], sk_x['s_x'], q)) % q

        denominator = (pow(ct['C'], sk_x['s_x'], q) *
                       pow(ct['D'], sk_x['t_x'], q)) % q

        # 计算模逆元
        denominator_inv = self._mod_inverse(denominator, q)
        E_x = (numerator * denominator_inv) % q

        # 计算离散对数 log_g(E_x)，这里简化处理，假设在小群中可以计算
        # 实际应用中需要使用Pollard's kangaroo方法等
        inner_product = self._discrete_log(E_x, mpk['g'], q)
        return inner_product

    def _mod_inverse(self, a: int, m: int) -> int:
        """计算a在模m下的逆元"""
        g, x, _ = self._extended_gcd(a, m)
        if g != 1:
            raise ValueError("模逆元不存在")
        return x % m

    def _extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """扩展欧几里得算法"""
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = self._extended_gcd(b % a, a)
            return g, x - (b // a) * y, y

    def _discrete_log(self, y: int, g: int, p: int) -> int:
        """
        简化的离散对数计算，仅用于小素数测试
        实际应用中应使用Pollard's kangaroo等算法
        """
        # 注意：此方法仅适用于小素数，大素数下不可行
        for x in range(p):
            if pow(g, x, p) == y:
                return x
        raise ValueError("离散对数不存在或无法计算")


# 测试方案
def test_ddh_fe():
    # 设置安全参数和向量维度
    security_param = 16  # 仅用于测试，实际应使用更大的值
    l = 2  # 2维向量

    # 初始化方案
    fe = DDHFunctionalEncryption(security_param)

    # 系统设置
    mpk, msk = fe.setup(l)
    print(f"公钥: {mpk}")
    print(f"主密钥: {msk}")

    # 生成密钥
    x = [3, 4]  # 向量x
    sk_x = fe.keygen(msk, x)
    print(f"密钥sk_x: {sk_x}")

    # 加密向量y
    y = [1, 2]  # 向量y
    ct = fe.encrypt(mpk, y)
    print(f"密文: {ct}")

    # 解密获取内积
    inner_product = fe.decrypt(mpk, sk_x, ct)
    print(f"计算的内积: {inner_product}")
    print(f"实际内积<x, y>: {x[0] * y[0] + x[1] * y[1]}")

    # 验证正确性
    assert inner_product == (x[0] * y[0] + x[1] * y[1]) % fe.q, "内积计算错误"
    print("测试通过!")


if __name__ == "__main__":
    test_ddh_fe()







