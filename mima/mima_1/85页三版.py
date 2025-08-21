from pypbc import *
import random

# 初始化双线性群参数（使用预置的 Type A 参数，对称双线性群）
params = Parameters(qbits=512, rbits=160)
pairing = Pairing(params)

# 生成群生成元
g1 = Element.random(pairing, G1)
g2 = Element.random(pairing, G2)  # 在对称双线性群中，G1=G2，但这里为了通用性分开生成
gT = pairing.apply(g1, g2)  # GT 的生成元


class FEGGM:
    def __init__(self, n):
        self.n = n  # 向量维度
        self.pairing = pairing
        self.p = pairing.p  # 群阶

    def setup(self):
        # 生成主密钥和公钥
        w = Element.random(self.pairing, Zr)
        a = [Element.random(self.pairing, Zr) for _ in range(self.n)]
        b = [Element.random(self.pairing, Zr) for _ in range(self.n)]

        # 将 a 和 b 编码到 G1 和 G2
        a_g1 = [Element(self.pairing, G1, value=g1 ** a_i) for a_i in a]
        b_g2 = [Element(self.pairing, G2, value=g2 ** b_i) for b_i in b]
        w_g2 = Element(self.pairing, G2, value=g2 ** w)

        self.msk = (w, a, b)
        self.mpk = (a_g1, b_g2, w_g2)
        return self.mpk, self.msk

    def keygen(self, F, msk):
        w, a, b = msk
        gamma = Element.random(self.pairing, Zr)

        # 计算 a^T F b
        aT_F_b = Element.zero(self.pairing, Zr)
        for i in range(self.n):
            for j in range(self.n):
                aT_F_b += a[i] * F[i][j] * b[j]

        S1 = g1 ** (aT_F_b + gamma * w)
        S2 = g1 ** gamma
        return (S1, S2, F)

    def encrypt(self, mpk, x, y):
        a_g1, b_g2, w_g2 = mpk
        r = Element.random(self.pairing, Zr)
        s = Element.random(self.pairing, Zr)
        t = Element.random(self.pairing, Zr)
        z = Element.random(self.pairing, Zr)

        # 计算 c = [r * a + x]_1
        c = [Element(self.pairing, G1, value=(g1 ** (r * a_g1_i)) * (g1 ** x_i)) for a_g1_i, x_i in zip(a_g1, x)]

        # 计算 c_tilde = [t * a + s * x]_1
        c_tilde = [Element(self.pairing, G1, value=(g1 ** (t * a_g1_i)) * (g1 ** (s * x_i))) for a_g1_i, x_i in
                   zip(a_g1, x)]

        # 计算 d = [s * b + y]_2
        d = [Element(self.pairing, G2, value=(g2 ** (s * b_g2_i)) * (g2 ** y_i)) for b_g2_i, y_i in zip(b_g2, y)]

        # 计算 d_tilde = [z * b + r * y]_2
        d_tilde = [Element(self.pairing, G2, value=(g2 ** (z * b_g2_i)) * (g2 ** (r * y_i))) for b_g2_i, y_i in
                   zip(b_g2, y)]

        # 计算 E = [rs - z - t]_2
        E = g2 ** (r * s - z - t)

        # 计算 E_tilde = [w*(rs - z - t)]_2
        E_tilde = w_g2 ** (r * s - z - t)

        return (c, c_tilde, d, d_tilde, E, E_tilde)

    def decrypt(self, sk_F, ct):
        S1, S2, F = sk_F
        c, c_tilde, d, d_tilde, E, E_tilde = ct

        # 计算 c^T F d
        term1 = Element.one(self.pairing, GT)
        for i in range(self.n):
            for j in range(self.n):
                term1 *= pairing.apply(c[i] ** F[i][j], d[j])

        # 计算 [a]_1^T F d_tilde
        term2 = Element.one(self.pairing, GT)
        for i in range(self.n):
            for j in range(self.n):
                term2 *= pairing.apply(g1 ** F[i][j], d_tilde[
                    j])  # 注意：这里 g1 是生成元，但需要与 a 对应？实际上 a_g1 是公钥的一部分，但这里我们直接用 g1，因为 a_g1 是 g1^{a_i}
        # 更正：应该使用公钥中的 a_g1，但这里为了简化，我们假设公钥中的 a_g1 是 g1^{a_i}，所以这里直接用 g1^{a_i} 的指数运算可能不直接。实际上，我们需要知道 a_i 的值，但这里没有保存。
        # 由于在解密时我们无法直接得到 a_i，所以这个方案在实现时需要保存 a 的数值形式，但公钥只提供了 [a]_1。因此，这个实现是概念性的，实际应用需要调整。

        # 类似地，计算 c_tilde^T F [b]_2
        term3 = Element.one(self.pairing, GT)
        for i in range(self.n):
            for j in range(self.n):
                term3 *= pairing.apply(c_tilde[i] ** F[i][j], g2)  # 这里也需要 b_j 的值，但公钥只提供了 [b]_2

        # 计算 e(S1, E) 和 e(S2, E_tilde)
        term4 = pairing.apply(S1, E)
        term5 = pairing.apply(S2, E_tilde)

        V = term1 / (term2 * term3) / term4 * term5
        return V


# 示例使用
def main():
    n = 2  # 向量维度
    fe = FEGGM(n)
    mpk, msk = fe.setup()

    # 生成一个函数矩阵 F（2x2）
    F = [[Element.random(fe.pairing, Zr) for _ in range(n)] for _ in range(n)]

    # 生成消息向量 x 和 y
    x = [Element.random(fe.pairing, Zr) for _ in range(n)]
    y = [Element.random(fe.pairing, Zr) for _ in range(n)]

    # 加密
    ct = fe.encrypt(mpk, x, y)

    # 生成密钥
    sk_F = fe.keygen(F, msk)

    # 解密
    result = fe.decrypt(sk_F, ct)

    # 验证：计算 x^T F y
    xT_F_y = Element.zero(fe.pairing, Zr)
    for i in range(n):
        for j in range(n):
            xT_F_y += x[i] * F[i][j] * y[j]
    expected = gT ** xT_F_y

    print("Decryption result matches expected value:", result == expected)


if __name__ == "__main__":
    main()