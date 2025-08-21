import numpy as np
import matplotlib.pyplot as plt
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# 设置中文字体支持
plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False


# 1. 模拟一个简单的加密函数（替代密码）
def simple_cipher(plaintext, key):
    """简单的替换加密函数"""
    ciphertext = []
    for char in plaintext:
        # 将字符转换为ASCII值
        ascii_val = ord(char)
        # 应用简单的线性变换 (模拟加密)
        encrypted_val = (ascii_val * key) % 256
        ciphertext.append(encrypted_val)
    return np.array(ciphertext)





# 2. 生成训练数据
def generate_data(num_samples, key):
    """生成加密数据样本"""
    plaintexts = []
    ciphertexts = []

    for _ in range(num_samples):
        # 生成随机文本 (模拟不同输入)
        length = np.random.randint(5, 20)
        plaintext: str = ''.join([chr(np.random.randint(65, 90)) for _ in range(length)])
        plaintexts.append(plaintext)

        # 加密文本
        ciphertext = simple_cipher(plaintext, key)
        # print("明文",plaintext)
        # print("密文",ciphertext)
        ciphertexts.append(ciphertext)

    return plaintexts, ciphertexts





# 3. 准备训练数据
key = 37  # 加密密钥
plaintexts, ciphertexts = generate_data(1000, key)

# 将数据转换为固定长度的特征向量
max_len = max(len(ct) for ct in ciphertexts)
X = np.zeros((len(ciphertexts), max_len))

for i, ct in enumerate(ciphertexts):
    X[i, :len(ct)] = ct

# 创建标签：区分加密文本和随机噪声
y = np.ones(len(ciphertexts))  # 真实加密文本标签为1

# 添加随机噪声作为负样本
noise_samples = np.random.randint(0, 256, (200, max_len))
X = np.vstack([X, noise_samples])
y = np.hstack([y, np.zeros(200)])  # 噪声标签为0

# 4. 训练神经网络进行加密分析
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 创建多层感知器分类器
mlp = MLPClassifier(
    hidden_layer_sizes=(50, 30),
    activation='relu',
    solver='adam',
    alpha=0.001,
    learning_rate_init=0.01,
    max_iter=500,
    random_state=42,
    verbose=True 
)

# 训练模型
mlp.fit(X_train, y_train)




# 5. 评估模型
train_pred = mlp.predict(X_train)
test_pred = mlp.predict(X_test)

print(f"训练准确率: {accuracy_score(y_train, train_pred):.4f}")
print(f"测试准确率: {accuracy_score(y_test, test_pred):.4f}")




# 6. 可视化训练过程中的梯度变化
plt.figure(figsize=(12, 6))

# 绘制损失曲线
plt.subplot(1, 2, 1)
plt.plot(mlp.loss_curve_)
plt.title('训练损失曲线')
plt.xlabel('迭代次数')
plt.ylabel('损失值')
plt.grid(alpha=0.3)

# 可视化梯度变化
plt.subplot(1, 2, 2)

# 获取权重梯度 (简化示例)
if hasattr(mlp, '_coef_grads'):
    # 取第一层的梯度变化
    layer_grads = np.array([np.mean(np.abs(g[0])) for g in mlp._coef_grads])
    plt.plot(layer_grads, 'r-', label='平均梯度大小')

    # 添加移动平均线
    window_size = 10
    moving_avg = np.convolve(layer_grads, np.ones(window_size) / window_size, mode='valid')
    plt.plot(range(window_size - 1, len(layer_grads)), moving_avg, 'b--', label='梯度移动平均')

    plt.title('训练过程中梯度变化')
    plt.xlabel('迭代次数')
    plt.ylabel('梯度大小')
    plt.legend()
    plt.grid(alpha=0.3)
else:
    plt.text(0.5, 0.5, '梯度数据不可用\n(不同sklearn版本支持不同)',
             ha='center', va='center', fontsize=12)

plt.tight_layout()
plt.suptitle('密码分析中的梯度应用', fontsize=16, y=1.03)
plt.show()


# 7. 使用梯度分析加密强度
def analyze_cipher_sensitivity(key, test_plaintext="HELLO"):
    """分析密码函数对密钥微小变化的敏感性"""
    original = simple_cipher(test_plaintext, key)

    sensitivities = []
    key_changes = np.linspace(-0.1, 0.1, 50)

    for delta in key_changes:
        changed_key = key + delta
        changed = simple_cipher(test_plaintext, changed_key)

        # 计算输出差异 (L1距离)
        diff = np.sum(np.abs(original - changed))
        sensitivities.append(diff)

    # 可视化敏感性
    plt.figure(figsize=(10, 6))
    plt.plot(key_changes, sensitivities, 'b-o')
    plt.axvline(x=0, color='r', linestyle='--', alpha=0.5)
    plt.title('密码函数对密钥变化的敏感性')
    plt.xlabel('密钥变化量')
    plt.ylabel('密码输出变化量 (L1距离)')
    plt.grid(alpha=0.3)
    plt.show()

    # 计算梯度 (变化率的近似)
    gradient = np.gradient(sensitivities, key_changes)
    max_gradient = np.max(np.abs(gradient))
    print(f"最大梯度值: {max_gradient:.4f} (表示密码函数的最大敏感性)")

    return sensitivities, gradient


# 运行敏感性分析
sensitivities, gradient = analyze_cipher_sensitivity(key)