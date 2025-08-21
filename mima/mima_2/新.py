import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt


class QuadraticMIFE:
    """二次多输入函数加密(qMIFE)模拟器"""

    def __init__(self, n_clients):
        self.n_clients = n_clients
        self.reset_instance()

    def reset_instance(self):
        """每轮迭代创建新实例防御密钥复用攻击"""
        self.ek = {i: f"EK_{np.random.randint(1000)}" for i in range(self.n_clients)}
        self.msk = f"MSK_{np.random.randint(1000)}"
        self.sk_cache = {}

    def encrypt(self, client_id, data):
        """客户端数据加密（模拟）"""
        return f"CT_{client_id}_{hash(tuple(data.flatten())) % 1000}"

    def keygen(self, func_vector):
        """TTP生成函数密钥（模拟）"""
        key_id = hash(tuple(func_vector.flatten())) % 1000
        self.sk_cache[key_id] = func_vector
        return f"SK_{key_id}"

    def decrypt(self, ciphertexts, sk_id):
        """聚合器解密梯度分量（模拟函数内积）"""
        func_vector = self.sk_cache[int(sk_id.split('_')[1])]
        # 模拟 ⟨c, x⊗x⟩ 内积计算
        total_dim = sum(c.shape[0] for c in ciphertexts.values())
        x = np.zeros(total_dim)
        idx = 0
        for cid, ct in ciphertexts.items():
            data_size = len(ct.split('_')[2])  # 模拟数据维度
            x[idx:idx + data_size] = np.frombuffer(ct.split('_')[2].encode(), dtype=np.float32)
            idx += data_size
        return np.dot(func_vector, x)


class VerticalFLSystem:
    """垂直联邦学习系统"""

    def __init__(self, n_clients, feature_dims, total_samples):
        self.n_clients = n_clients
        self.feature_dims = feature_dims  # 各客户端特征维度
        self.total_features = sum(feature_dims)
        self.total_samples = total_samples
        self.crypto = QuadraticMIFE(n_clients)

        # 生成模拟数据
        self.X, self.y = self.generate_vertical_data()
        self.weights = np.random.randn(self.total_features)

        # 存储中间结果
        self.gradient_history = []
        self.loss_history = []

    def generate_vertical_data(self):
        """生成垂直分区数据"""
        # 真实特征 + 噪声
        X_real = np.random.randn(self.total_samples, self.total_features)
        y = X_real @ np.random.randn(self.total_features) + 0.1 * np.random.randn(self.total_samples)

        # 垂直分区
        X_partitioned = {}
        start_idx = 0
        for i, dim in enumerate(self.feature_dims):
            X_partitioned[i] = X_real[:, start_idx:start_idx + dim]
            start_idx += dim
        return X_partitioned, y

    def construct_func_vector(self, client_id, feature_idx):
        """构造函数向量c_i,p (算法2简化实现)"""
        # 论文核心创新：设计特殊向量使解密结果=梯度分量
        c = np.zeros(self.total_features ** 2)

        # 目标位置设权重值 (模拟论文中的系数设计)
        target_idx = sum(self.feature_dims[:client_id]) * self.total_features + feature_idx
        c[target_idx] = -2.0 * self.weights[feature_idx]  # 来自公式(2)

        # 标签持有客户端的特殊处理
        if client_id == 0:
            label_idx = self.total_features * feature_idx
            c[label_idx] = 2.0  # 来自公式(2)的y^T X_i项

        return c

    def client_encrypt_data(self, client_id, batch_X):
        """客户端加密数据 (算法1步骤28-35)"""
        # 向量化数据 (vec(X_i))
        vec_data = batch_X.flatten()
        # 标签持有者额外加密标签
        if client_id == 0:
            return (
                self.crypto.encrypt(client_id, vec_data),
                self.crypto.encrypt(client_id, self.y_batch)
            )
        return self.crypto.encrypt(client_id, vec_data)

    def secure_gradient_computation(self, batch_size):
        """安全梯度计算 (算法1核心流程)"""
        # 1. 选择批次数据
        batch_idx = np.random.choice(self.total_samples, batch_size, replace=False)
        self.y_batch = self.y[batch_idx]

        # 2. 客户端加密数据
        ciphertexts = {}
        for cid in range(self.n_clients):
            batch_X = self.X[cid][batch_idx]
            if cid == 0:  # 标签持有者
                ct_data, ct_label = self.client_encrypt_data(cid, batch_X)
                ciphertexts[cid] = ct_data
                ciphertexts['label'] = ct_label
            else:
                ciphertexts[cid] = self.client_encrypt_data(cid, batch_X)

        # 3. 聚合器构造函数向量并获取密钥
        gradient_components = []
        for cid in range(self.n_clients):
            for fidx in range(self.feature_dims[cid]):
                c_vector = self.construct_func_vector(cid, fidx)
                sk = self.crypto.keygen(c_vector)

                # 4. 解密梯度分量 (模拟⟨c, x⊗x⟩)
                comp = self.crypto.decrypt(ciphertexts, sk.split('_')[1])
                gradient_components.append(comp)

        # 5. 拼接完整梯度
        gradient = np.array(gradient_components) / batch_size
        return gradient

    def train(self, n_iters, batch_size, lr=0.01):
        """安全联邦训练过程"""
        for iter in range(n_iters):
            # 每轮使用新qMIFE实例
            self.crypto.reset_instance()

            # 安全梯度计算
            gradient = self.secure_gradient_computation(batch_size)

            # 权重更新
            self.weights -= lr * gradient

            # 记录历史
            self.gradient_history.append(np.linalg.norm(gradient))
            loss = np.mean((self.y - self.predict()) ** 2)
            self.loss_history.append(loss)

            print(f"Iter {iter + 1}: Loss={loss:.4f}, GradNorm={self.gradient_history[-1]:.4f}")

    def predict(self):
        """预测全量数据"""
        full_X = np.hstack([self.X[i] for i in range(self.n_clients)])
        return full_X @ self.weights

    def visualize_training(self):
        """可视化训练过程"""
        plt.figure(figsize=(12, 4))
        plt.subplot(121)
        plt.plot(self.loss_history)
        plt.title('Training Loss')
        plt.xlabel('Iteration')
        plt.ylabel('MSE Loss')

        plt.subplot(122)
        plt.plot(self.gradient_history)
        plt.title('Gradient Norm')
        plt.xlabel('Iteration')
        plt.ylabel('L2 Norm')
        plt.tight_layout()
        plt.savefig('secure_vfl_training.png')
        plt.show()


# 系统参数配置
n_clients = 3
feature_dims = [4, 3, 2]  # 各客户端特征维度
total_samples = 1000
batch_size = 32
n_iters = 50

# 初始化并训练系统
vfl_system = VerticalFLSystem(n_clients, feature_dims, total_samples)
print("Initial MSE:", np.mean((vfl_system.y - vfl_system.predict()) ** 2))
vfl_system.train(n_iters, batch_size)
print("Final MSE:", np.mean((vfl_system.y - vfl_system.predict()) ** 2))

# 可视化结果
vfl_system.visualize_training()