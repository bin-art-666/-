import random
from typing import List, Tuple, Dict


# 模拟素数阶循环群
class PrimeGroup:
    def __init__(self, q: int):
        self.q = q       # 群阶
        self.g = self._generate_generator()
        self.h = self._generate_generator()

    #生成一个生成元
    def _generate_generator(self) -> int:
        # 生成器
        while True:
            g = random.randint(2, self.q - 1)
            if all( pow(g, (self.q - 1)  // p,  self.q)   != 1 for p in self._prime_factors(self.q - 1)):
                return g

    # 对n质因数分解
    def _prime_factors(self, n: int) -> List[int]:
        factors = set()
        temp = n
        i = 2
        while i * i <= temp:
            if temp % i == 0:
                factors.add(i)
                while temp % i == 0:
                    temp //= i
            i += 1
        if temp > 1:
            factors.add(temp)
        return list(factors)

    # 模指数运算  base的exp次方对q取模
    def exp(self, base: int, exp: int) -> int:
        return pow(base, exp, self.q)


# 输入安全参数与向量维度 生成主公钥和主私钥
def setup(lambda_param: int, l: int) -> Tuple[Dict, List[Tuple[int, int]]]:
    q = 2 ** lambda_param - 1  # 示例素数
    group = PrimeGroup(q)  #素数阶循环群
    msk = []       #Master Secret Key  主私钥
    h_list = []
    for _ in range(l):
        s_i = random.randint(0, q - 1)
        t_i = random.randint(0, q - 1)
        msk.append((s_i, t_i))
        h_i = (group.exp(group.g, s_i) * group.exp(group.h, t_i)) % group.q
        h_list.append(h_i)
    mpk = {
        "group": group,
        "g": group.g,
        "h": group.h,
        "h_list": h_list,
        "q": group.q
    }
    return mpk, msk  # 主公钥  主私钥


# 2. Keygen算法
def keygen(mpk: Dict, msk: List[Tuple[int, int]], x: List[int]) -> Tuple[int, int]:
    q = mpk["q"]
    s_total = sum(s * xi for (s, t), xi in zip(msk, x)) % q
    t_total = sum(t * xi for (s, t), xi in zip(msk, x)) % q
    return (s_total, t_total)


# 3. Encrypt算法
def encrypt(mpk: Dict, y: List[int]) -> Tuple[int, int, List[int]]:
    group = mpk["group"]
    q = mpk["q"]
    g, h = mpk["g"], mpk["h"]
    h_list = mpk["h_list"]
    l = len(h_list)
    r = random.randint(0, q - 1)  # 随机指数r
    C = group.exp(g, r)
    D = group.exp(h, r)
    E_list = []
    for yi, hi in zip(y, h_list):
        E_i = (group.exp(g, yi) * group.exp(hi, r)) % q
        E_list.append(E_i)
    return (C, D, E_list)


# 4. Decrypt算法（需解决离散对数问题，仅演示逻辑）
def decrypt(mpk: Dict, sk_x: Tuple[int, int], ciphertext: Tuple[int, int, List[int]], x: List[int]) -> int:
    group = mpk["group"]
    q = mpk["q"]
    C, D, E_list = ciphertext
    s_x, t_x = sk_x
    # 计算分子：乘积(E_i^x_i)
    numerator = 1
    for xi, Ei in zip(x, E_list):
        numerator = (numerator * group.exp(Ei, xi)) % q
    # 计算分母：C^s_x * D^t_x
    denominator = (group.exp(C, s_x) * group.exp(D, t_x)) % q
    # 计算E_x = numerator * denominator^{-1} mod q
    E_x = (numerator * pow(denominator, -1, q)) % q
    # 求解离散对数（实际需使用Pollard's Rho等算法，此处仅演示小范围暴力搜索）
    for inner_prod in range(q):
        if group.exp(group.g, inner_prod) == E_x:
            return inner_prod
    raise ValueError("离散对数未找到解")


# 示例用法
if __name__ == "__main__":
    lambda_param = 5  # 安全参数调整为5，使得q=31为素数
    l = 3  # 向量维度
    mpk, msk = setup(lambda_param, l)

    # 测试向量
    x = [1, 2, 3]  # 私钥向量（简化以便验证）
    y = [4, 5, 6]  # 消息向量（内积为32 mod 31=1）

    sk_x = keygen(mpk, msk, x)
    ct = encrypt(mpk, y)            #密文
    # 解密时需传入私钥对应的向量x
    result = decrypt(mpk, sk_x, ct, x)

    # 验证正确性（理论上应等于内积mod q）
    expected = sum(xi * yi for xi, yi in zip(x, y)) % mpk["q"]
    print(f"内积结果: {result}")
    print(f"预期结果: {expected}")
    assert result == expected, "解密错误"



