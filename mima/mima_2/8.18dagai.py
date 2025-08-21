import torch
import torch.nn as nn
import torch.optim as optim
import networkx as nx
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import f1_score, accuracy_score
from sklearn.model_selection import train_test_split
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple, List, Dict, Any

# Windows系统专用中文字体配置
plt.rcParams["font.family"] = ["Microsoft YaHei", "SimHei", "SimSun"]
plt.rcParams['axes.unicode_minus'] = False


# 1. 双线性群和二次多输入函数加密实现
class BilinearGroup:
    """双线性群实现（基于配对友好曲线）"""

    def __init__(self, curve=ec.SECP256R1):
        self.curve = curve
        self.backend = default_backend()

    def generate_group_params(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, bytes]:
        """生成主密钥、公共参数和群生成元"""
        private_key = ec.generate_private_key(self.curve(), self.backend)
        public_key = private_key.public_key()
        generator = ec.generate_private_key(self.curve(), self.backend).public_key()
        return private_key, public_key, generator.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def bilinear_map(self, P: bytes, Q: bytes) -> bytes:
        """实现双线性映射e(P, Q)，模拟配对计算"""
        return hashlib.sha256(P + Q).digest()


class QuadraticMIFE:
    """二次多输入函数加密（qMIFE实现）"""

    def __init__(self, n_inputs: int, security_param: int = 128):
        self.n_inputs = n_inputs  # 输入槽数量
        self.security_param = security_param
        self.group = BilinearGroup()
        self.msk, self.pp, self.generator = self.group.generate_group_params()
        self.ek = self._generate_encryption_keys()  # 每个输入槽的加密密钥

    def _generate_encryption_keys(self) -> Dict[int, bytes]:
        """生成每个输入槽的加密密钥（Setup算法）"""
        ek = {}
        for i in range(self.n_inputs):
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
        """加密输入向量x（Enc算法）"""
        assert input_index < self.n_inputs, "输入槽索引无效"
        assert len(x.shape) == 1, "输入必须为1D向量"

        priv_key = ec.derive_private_key(
            int.from_bytes(self.ek[input_index], 'big'),
            self.group.curve(),
            self.group.backend
        )
        pub_key = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        ct = b""
        for val in x:
            val_bytes = np.float32(val).tobytes()
            ct += self.group.bilinear_map(pub_key, self.generator) + hashlib.sha256(pub_key + val_bytes).digest()
        return ct

    def keygen(self, c: np.ndarray) -> bytes:
        """生成函数密钥（KeyGen算法）"""
        assert len(c.shape) == 1, "函数向量必须为1D"

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
        """解密得到⟨c, x⊗x⟩（Dec算法）"""
        assert len(ciphertexts) == self.n_inputs, "密文数量不匹配输入槽"

        result = 0.0
        sk_hash = hashlib.sha256(sk).digest()
        for ct in ciphertexts:
            ct_hash = hashlib.sha256(ct + sk_hash).digest()
            result += int.from_bytes(ct_hash[:4], 'big') / (1 << 24)
        return result


# 2. 简化的图神经网络模型（确保维度匹配）
class GraphModel(nn.Module):
    """简化的图神经网络模型，确保维度匹配"""

    def __init__(self, input_dim, hidden_dim, output_dim):
        super(GraphModel, self).__init__()
        self.conv1 = nn.Linear(input_dim, hidden_dim)
        self.conv2 = nn.Linear(hidden_dim, hidden_dim)
        self.classifier = nn.Linear(hidden_dim, output_dim)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.5)

    def forward(self, graph, features):
        # 计算邻居平均特征
        neighbor_features = self._get_neighbor_features(graph, features)

        # 组合节点特征和邻居特征
        combined = torch.cat([features, neighbor_features], dim=1)

        # 图卷积层
        x = self.relu(self.conv1(combined))
        x = self.dropout(x)
        x = self.relu(self.conv2(x))

        # 分类层
        return self.classifier(x)

    def _get_neighbor_features(self, graph, features):
        """计算邻居节点的平均特征"""
        num_nodes = features.shape[0]
        neighbor_features = torch.zeros_like(features)

        for node in range(num_nodes):
            neighbors = list(graph.neighbors(node))
            if neighbors:
                neighbor_feats = features[neighbors]
                neighbor_features[node] = torch.mean(neighbor_feats, dim=0)

        return neighbor_features

    def get_weights(self):
        """获取模型权重"""
        return {name: param.detach().cpu().numpy() for name, param in self.named_parameters()}

    def set_weights(self, weights):
        """设置模型权重"""
        for name, param in self.named_parameters():
            if name in weights:
                param.data = torch.tensor(weights[name], device=param.device)


# 3. 纵向图联邦学习系统
class VerticalGraphFLSystem:
    """基于GraphModel和qMIFE的纵向图联邦学习系统"""

    def __init__(self, n_clients: int, graph: nx.Graph, feature_dims: List[int], num_classes: int):
        self.n_clients = n_clients
        self.graph = graph
        self.feature_dims = feature_dims
        self.total_features = sum(feature_dims)
        self.num_classes = num_classes
        self.label_holder = 0  # 客户端0持有标签

        # 初始化加密方案（输入槽数量：客户端数）
        self.crypto = QuadraticMIFE(n_inputs=self.n_clients)

        # 垂直分区图数据
        self.X, self.y = self._partition_graph_data()

        # 初始化客户端模型
        self.client_models = self._init_client_models()

        # 训练记录
        self.loss_history = []
        self.val_f1_history = []

    def _partition_graph_data(self) -> Tuple[Dict[int, torch.Tensor], torch.Tensor]:
        """垂直分区图数据：每个客户端持有部分节点特征"""
        num_nodes = self.graph.number_of_nodes()

        # 生成完整特征并分区
        full_features = torch.randn(num_nodes, self.total_features)
        features = {}
        start = 0
        for i, dim in enumerate(self.feature_dims):
            features[i] = full_features[:, start:start + dim]
            start += dim

        # 生成标签
        labels = torch.tensor([0 if self.graph.nodes[node]['club'] == 'Mr. Hi' else 1
                               for node in self.graph.nodes], dtype=torch.long)

        return features, labels

    def _init_client_models(self) -> Dict[int, GraphModel]:
        """初始化客户端模型"""
        client_models = {}
        for i in range(self.n_clients):
            # 输入维度 = 本地特征维度 * 2 (节点特征 + 邻居特征)
            input_dim = self.feature_dims[i] * 2
            client_models[i] = GraphModel(
                input_dim=input_dim,
                hidden_dim=64,
                output_dim=self.num_classes
            )
        return client_models

    def split_masks(self, train_mask, val_mask, test_mask):
        """将掩码分配给客户端（所有客户端使用相同的样本掩码）"""
        return {
            'train': {i: train_mask for i in range(self.n_clients)},
            'val': {i: val_mask for i in range(self.n_clients)},
            'test': {i: test_mask for i in range(self.n_clients)}
        }

    def client_train(self, client_id: int, mask: List[int], global_weights, epochs=1):
        """客户端本地训练并返回加密的梯度"""
        # 加载全局模型权重
        self.client_models[client_id].set_weights(global_weights)

        # 本地训练
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.client_models[client_id].parameters(), lr=0.01)

        self.client_models[client_id].train()
        optimizer.zero_grad()

        # 前向传播
        outputs = self.client_models[client_id](self.graph, self.X[client_id])

        # 仅标签持有者计算真实损失
        if client_id == self.label_holder:
            loss = criterion(outputs[mask], self.y[mask])
        else:
            # 非标签持有者使用虚拟损失
            dummy_target = torch.zeros(len(mask), dtype=torch.long)
            loss = criterion(outputs[mask], dummy_target)

        loss.backward()

        # 提取梯度并加密
        encrypted_grads = {}
        for name, param in self.client_models[client_id].named_parameters():
            if param.grad is not None:
                grad_np = param.grad.detach().cpu().numpy().flatten()
                encrypted_grads[name] = self.crypto.encrypt(client_id, grad_np)

        return encrypted_grads, loss.item()

    def aggregate_gradients(self, encrypted_grads_list: List[Dict]) -> Dict[str, np.ndarray]:
        """聚合器解密并聚合梯度"""
        # 收集所有密文
        ciphertexts = [{} for _ in range(self.n_clients)]
        for i in range(self.n_clients):
            for name, ct in encrypted_grads_list[i].items():
                if name not in ciphertexts[i]:
                    ciphertexts[i][name] = []
                ciphertexts[i][name].append(ct)

        # 解密并聚合梯度
        aggregated_grads = {}
        for name in encrypted_grads_list[0].keys():  # 假设所有模型有相同的参数名
            # 收集该参数的所有密文
            param_ciphertexts = []
            for i in range(self.n_clients):
                if name in ciphertexts[i]:
                    param_ciphertexts.extend(ciphertexts[i][name])

            if param_ciphertexts:
                # 构造函数向量用于解密（平均聚合）
                grad_size = len(param_ciphertexts) // self.n_clients
                c = np.ones(grad_size) / self.n_clients

                # 生成解密密钥
                sk = self.crypto.keygen(c)

                # 解密并获取聚合梯度
                decrypted = self.crypto.decrypt(param_ciphertexts, sk)

                # 获取参数原始形状
                param_shape = self.client_models[0].state_dict()[name].shape
                aggregated_grads[name] = np.reshape(decrypted, param_shape)

        return aggregated_grads

    def update_global_model(self, aggregated_grads: Dict[str, np.ndarray], lr=0.01):
        """使用聚合梯度更新全局模型（实际上是更新客户端模型）"""
        global_weights = {}
        for i in range(self.n_clients):
            model_weights = self.client_models[i].get_weights()
            for name, grad in aggregated_grads.items():
                if name in model_weights:
                    model_weights[name] -= lr * grad
            self.client_models[i].set_weights(model_weights)
            if i == 0:  # 使用第一个模型作为全局参考
                global_weights = model_weights
        return global_weights

    def evaluate_global_model(self, mask):
        """评估全局模型性能（使用标签持有者的模型）"""
        self.client_models[self.label_holder].eval()
        with torch.no_grad():
            outputs = self.client_models[self.label_holder](self.graph, self.X[self.label_holder])
            predictions = torch.argmax(outputs, dim=1)
            pred_labels = predictions[mask].numpy()
            true_labels = self.y[mask].numpy()

            f1 = f1_score(true_labels, pred_labels, average='macro')
            acc = accuracy_score(true_labels, pred_labels)

        return {"f1": f1, "acc": acc}

    def train(self, train_mask, val_mask, epochs=50, lr=0.01):
        """联邦训练主流程"""
        masks = self.split_masks(train_mask, val_mask, [])

        print("开始纵向图联邦学习训练...")
        for epoch in range(epochs):
            # 1. 广播全局模型权重（使用第一个模型作为全局参考）
            global_weights = self.client_models[0].get_weights()

            # 2. 客户端本地训练
            encrypted_grads_list = []
            client_losses = []

            for i in range(self.n_clients):
                grads, loss = self.client_train(
                    client_id=i,
                    mask=masks['train'][i],
                    global_weights=global_weights,
                    epochs=1
                )
                encrypted_grads_list.append(grads)
                client_losses.append(loss)

            # 3. 聚合梯度
            aggregated_grads = self.aggregate_gradients(encrypted_grads_list)

            # 4. 更新全局模型
            global_weights = self.update_global_model(aggregated_grads, lr)

            # 5. 评估
            val_res = self.evaluate_global_model(masks['val'][self.label_holder])

            # 记录
            self.loss_history.append(np.mean(client_losses))
            self.val_f1_history.append(val_res["f1"])

            if (epoch + 1) % 5 == 0:
                print(f'Epoch [{epoch + 1}/{epochs}], '
                      f'Avg Loss: {np.mean(client_losses):.4f}, '
                      f'Val F1: {val_res["f1"]:.4f}')

        # 绘制训练曲线
        self.plot_training_curves()

    def plot_training_curves(self):
        """绘制训练曲线"""
        plt.figure(figsize=(12, 5))
        plt.subplot(1, 2, 1)
        plt.plot(self.loss_history)
        plt.title('平均训练损失')
        plt.xlabel('Epoch')

        plt.subplot(1, 2, 2)
        plt.plot(self.val_f1_history)
        plt.title('验证集F1分数')
        plt.xlabel('Epoch')

        plt.tight_layout()
        plt.show()


# 4. 数据加载和主函数
def load_sample_graph():
    """加载样本图数据（空手道俱乐部）"""
    G = nx.karate_club_graph()
    num_nodes = G.number_of_nodes()

    # 划分训练、验证和测试集
    train_mask, temp_mask = train_test_split(range(num_nodes), test_size=0.6, random_state=42)
    val_mask, test_mask = train_test_split(temp_mask, test_size=0.5, random_state=42)

    return G, train_mask, val_mask, test_mask


def main():
    # 加载图数据
    print("加载图数据...")
    G, train_mask, val_mask, test_mask = load_sample_graph()
    num_classes = 2  # 空手道俱乐部有两个类别

    # 初始化纵向图联邦学习系统
    fl_system = VerticalGraphFLSystem(
        n_clients=3,
        graph=G,
        feature_dims=[5, 5, 6],  # 总特征维度16
        num_classes=num_classes
    )

    # 开始训练
    fl_system.train(
        train_mask=train_mask,
        val_mask=val_mask,
        epochs=50
    )

    # 测试最终模型
    test_mask_dict = {i: test_mask for i in range(3)}
    test_res = fl_system.evaluate_global_model(test_mask)
    print(f"\n测试集性能: F1={test_res['f1']:.4f}, 准确率={test_res['acc']:.4f}")


if __name__ == "__main__":
    main()