import random
import numpy as np
from p.bn128 import G1, G2, add, multiply, neg, p, curve_order
from p.bn128.bn128_curve import normalize


# 辅助函数
def vector_add(v1, v2, p):
    return [(a + b) % p for a, b in zip(v1, v2)]


def vector_scale(k, v, p):
    return [(k * a) % p for a in v]


def matrix_mult(A, B, p):
    n = len(A)
    k = len(B)
    m = len(B[0])
    C = [[0] * m for _ in range(n)]
    for i in range(n):
        for j in range(m):
            for t in range(k):
                C[i][j] = (C[i][j] + A[i][t] * B[t][j]) % p
    return C


def matrix_vector_mult(M, v, p):
    n = len(M)
    k = len(v)
    res = [0] * n
    for i in range(n):
        for j in range(k):
            res[i] = (res[i] + M[i][j] * v[j]) % p
    return res


def vector_matrix_mult(v, M, p):
    n = len(M[0])
    k = len(v)
    res = [0] * n
    for j in range(n):
        for i in range(k):
            res[j] = (res[j] + v[i] * M[i][j]) % p
    return res


def inner_product(u, v, p):
    return sum(a * b for a, b in zip(u, v)) % p


def random_matrix(rows, cols, p):
    return [[random.randint(0, p - 1) for _ in range(cols)] for _ in range(rows)]


def random_vector(dim, p):
    return [random.randint(0, p - 1) for _ in range(dim)]


def invert_matrix(M, p):
    n = len(M)
    M = np.array(M, dtype=np.int64)
    I = np.eye(n, dtype=np.int64)
    M_inv = np.linalg.inv(M) % p
    return M_inv.tolist()


def random_invertible_matrix(dim, p):
    while True:
        M = random_matrix(dim, dim, p)
        try:
            M_inv = invert_matrix(M, p)
            return M, M_inv
        except np.linalg.LinAlgError:
            continue


# 方案实现
def Setup(lam, n, m, k):
    p = curve_order
    # 生成双线性群参数
    A = random_matrix(k, k, p)
    B = random_matrix(k, k, p)
    r_i = [random_vector(k, p) for _ in range(2 * n)]
    s_j = [random_vector(k, p) for _ in range(2 * m)]

    # 计算 [A r_i]_1 和 [B s_j]_2
    Ar_list = [matrix_vector_mult(A, r, p) for r in r_i]
    Bs_list = [matrix_vector_mult(B, s, p) for s in s_j]

    mpk = {
        'Ar_list': Ar_list,  # 2n个k维向量
        'Bs_list': Bs_list,  # 2m个k维向量
        'n': n, 'm': m, 'k': k, 'p': p
    }
    msk = {
        'A': A, 'B': B, 'r_i': r_i, 's_j': s_j
    }
    return mpk, msk


def KeyGen(msk, F):
    p = curve_order
    A = msk['A']
    B = msk['B']
    r_i = msk['r_i']
    s_j = msk['s_j']
    n = len(F)
    m = len(F[0])

    # 计算 K 的指数部分
    exponent = 0
    AT = [[A[j][i] for j in range(len(A))] for i in range(len(A[0]))]
    ATB = matrix_mult(AT, B, p)

    for i in range(n):
        for j in range(m):
            # 计算 r_i^T A^T B s_j
            r_i_vec = r_i[i]
            s_j_vec = s_j[j]
            term1 = inner_product(vector_matrix_mult(r_i_vec, ATB, p), s_j_vec, p)

            # 计算 r_{i+n}^T A^T B s_{j+m}
            r_in_vec = r_i[i + n]
            s_jm_vec = s_j[j + m]
            term2 = inner_product(vector_matrix_mult(r_in_vec, ATB, p), s_jm_vec, p)

            exponent = (exponent + F[i][j] * (term1 + term2)) % p

    u = random.randint(0, p - 1)
    K_exp = (exponent - u) % p
    O_exp = u  # Ō = [u]_2

    return (K_exp, O_exp)


def Encrypt(mpk, x, y):
    p = mpk['p']
    n = mpk['n']
    m = mpk['m']
    k = mpk['k']
    Ar_list = mpk['Ar_list']
    Bs_list = mpk['Bs_list']

    # 生成随机可逆矩阵 W, V
    W, W_inv = random_invertible_matrix(k + 2, p)
    V, V_inv = random_invertible_matrix(k + 2, p)
    gamma = random.randint(0, p - 1)

    # 初始化密文
    c0 = gamma
    c_i = [None] * (2 * n)
    O_j = [None] * (2 * m)

    # 处理 i ∈ [n]
    for i in range(n):
        # 扩展向量 (Ar_i, x_i, 0)
        vec = Ar_list[i] + [x[i], 0]
        scaled_vec = vector_scale(gamma, vec, p)
        c_i[i] = vector_matrix_mult(scaled_vec, W_inv, p)

    # 处理 i ∈ [n, 2n)
    for i in range(n, 2 * n):
        # 扩展向量 (Ar_i, 0, 0)
        vec = Ar_list[i] + [0, 0]
        scaled_vec = vector_scale(gamma, vec, p)
        c_i[i] = vector_matrix_mult(scaled_vec, V_inv, p)

    # 处理 j ∈ [m]
    for j in range(m):
        # 扩展向量 (Bs_j, y_j, 0)
        vec = Bs_list[j] + [y[j], 0]
        O_j[j] = matrix_vector_mult(W, vec, p)

    # 处理 j ∈ [m, 2m)
    for j in range(m, 2 * m):
        # 扩展向量 (Bs_j, 0, 0)
        vec = Bs_list[j] + [0, 0]
        O_j[j] = matrix_vector_mult(V, vec, p)

    return (c0, c_i, O_j)


def Decrypt(mpk, ct, skF, F):
    p = mpk['p']
    n = mpk['n']
    m = mpk['m']
    c0, c_i, O_j = ct
    K_exp, O_exp = skF

    # 计算配对乘积之和
    S = 0
    for i in range(n):
        for j in range(m):
            # e([c_i]_1, [Ō_j]_2)
            term1 = inner_product(c_i[i], O_j[j], p)
            # e([c_{n+i}]_1, [Ō_{m+j}]_2)
            term2 = inner_product(c_i[i + n], O_j[j + m], p)
            S = (S + F[i][j] * (term1 + term2)) % p

    # 计算配对项
    term3 = (c0 * O_exp) % p  # e([c0]_1, Ō)
    term4 = (K_exp * c0) % p  # e(K, [c0]_2)

    result = (S - term3 - term4) % p
    return result


# 测试示例
if __name__ == "__main__":
    # 参数设置
    lam = 128  # 安全参数
    n, m, k = 2, 2, 3  # 向量维度
    p = curve_order

    # 随机函数矩阵 F (n x m)
    F = [[random.randint(0, p - 1) for _ in range(m)] for _ in range(n)]

    # 输入向量 (x, y)
    x = [random.randint(0, p - 1) for _ in range(n)]
    y = [random.randint(0, p - 1) for _ in range(m)]

    # 运行方案
    mpk, msk = Setup(lam, n, m, k)
    skF = KeyGen(msk, F)
    ct = Encrypt(mpk, x, y)
    result = Decrypt(mpk, ct, skF, F)

    print(f"解密结果 (应为0): {result}")