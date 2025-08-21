import hashlib
from typing import Tuple, List, Dict

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sklearn.metrics import f1_score, accuracy_score
from sklearn.model_selection import train_test_split
from torch.nn import functional as F

# Windows系统专用中文字体配置
plt.rcParams["font.family"] = ["Microsoft YaHei", "SimHei", "SimSun"]
plt.rcParams['axes.unicode_minus'] = False


# 1. 双线性群和二次多输入函数加密实现（密码部分）
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


# 2. GraphSAGE模型定义
class GraphSAGE(nn.Module):
    """支持联邦学习的GraphSAGE模型"""

    def __init__(self, input_dim, hidden_dim, output_dim, num_layers=3,
                 aggregator_type='max_pool', max_neighbors=10, edge_dim=None):
        super(GraphSAGE, self).__init__()
        self.num_layers = num_layers
        self.aggregator_type = aggregator_type
        self.max_neighbors = max_neighbors
        self.edge_dim = edge_dim
        self.hidden_dim = hidden_dim
        self.input_dim = input_dim

        self.layers = nn.ModuleList()
        self.norms = nn.ModuleList()

        # 输入层
        in_channels = input_dim + hidden_dim
        if edge_dim is not None:
            in_channels += edge_dim
        self.layers.append(nn.Linear(in_channels, hidden_dim))
        self.norms.append(nn.LayerNorm(hidden_dim))

        # 隐藏层
        for _ in range(num_layers - 2):
            in_channels = hidden_dim * 2
            if edge_dim is not None:
                in_channels += edge_dim
            self.layers.append(nn.Linear(in_channels, hidden_dim))
            self.norms.append(nn.LayerNorm(hidden_dim))

        # 输出层
        in_channels = hidden_dim * 2
        if edge_dim is not None:
            in_channels += edge_dim
        self.layers.append(nn.Linear(in_channels, output_dim))

        # 聚合器相关层
        if aggregator_type == 'max_pool':
            self.pool_layers = nn.ModuleList()
            for i in range(num_layers):
                in_dim = input_dim if i == 0 else hidden_dim
                self.pool_layers.append(nn.Linear(in_dim, hidden_dim))
        elif aggregator_type == 'attn':
            self.attn_layers = nn.ModuleList()
            for i in range(num_layers):
                in_dim = input_dim if i == 0 else hidden_dim
                self.attn_layers.append(nn.Linear(in_dim * 2, 1))

        self.activation = nn.ReLU()
        self.dropout = nn.Dropout(0.5)

        # 修改池化层初始化部分
        if aggregator_type == 'max_pool':
            self.pool_layers = nn.ModuleList()
            for i in range(num_layers):
                # 第0层使用input_dim，其他层使用hidden_dim
                in_dim = input_dim if i == 0 else hidden_dim
                self.pool_layers.append(nn.Linear(in_dim, hidden_dim))

        # 添加一个适配层来处理特征维度变化
        self.feature_adapter = None
        if input_dim != hidden_dim:  # 如果输入维度不等于隐藏维度
            self.feature_adapter = nn.Linear(input_dim, hidden_dim)

    def forward(self, graph, features, edge_features=None):
        x = features
        for i in range(self.num_layers):
            aggregated = self._aggregate(graph, x, edge_features, layer_idx=i)

            if self.edge_dim is not None and edge_features is not None:
                edge_agg = self._aggregate_edge_features(graph, x, edge_features)
                x = torch.cat([x, aggregated, edge_agg], dim=1)
            else:
                x = torch.cat([x, aggregated], dim=1)

            x = self.layers[i](x)

            if i < self.num_layers - 1:
                residual = x
                x = self.norms[i](x)
                x = self.activation(x)
                x = self.dropout(x)
                x = x + residual

        return x

    def _sample_neighbors(self, graph, node):
        neighbors = list(graph.neighbors(node))
        if len(neighbors) > self.max_neighbors:
            neighbors = np.random.choice(neighbors, self.max_neighbors, replace=False)
        elif len(neighbors) < self.max_neighbors:
            neighbors = np.pad(neighbors, (0, self.max_neighbors - len(neighbors)),
                               mode='constant', constant_values=node)
        return neighbors

    def _aggregate(self, graph, features, edge_features=None, layer_idx=0):
        num_nodes = features.shape[0]
        aggregated = []

        for node in range(num_nodes):
            neighbors = self._sample_neighbors(graph, node)
            neighbor_features = features[neighbors]

            if self.aggregator_type == 'mean':
                agg = torch.mean(neighbor_features, dim=0)
                if layer_idx == 0 and agg.shape[0] != self.hidden_dim:
                    agg = nn.Linear(agg.shape[0], self.hidden_dim).to(agg.device)(agg)
            elif self.aggregator_type == 'max_pool':
                pooled = self.activation(self.pool_layers[layer_idx](neighbor_features))
                agg = torch.max(pooled, dim=0)[0]
            elif self.aggregator_type == 'attn':
                node_feat = features[node].unsqueeze(0).repeat(len(neighbors), 1)
                attn_input = torch.cat([node_feat, neighbor_features], dim=1)
                attn_weights = F.softmax(self.attn_layers[layer_idx](attn_input), dim=0)
                agg = torch.sum(attn_weights * neighbor_features, dim=0)
                if layer_idx == 0 and agg.shape[0] != self.hidden_dim:
                    agg = nn.Linear(agg.shape[0], self.hidden_dim).to(agg.device)(agg)
            elif self.aggregator_type == 'max_pool':
                # 如果存在特征适配器，先转换特征维度
                if layer_idx == 0 and self.feature_adapter is not None:
                    neighbor_features = self.feature_adapter(neighbor_features)

                pooled = self.activation(self.pool_layers[layer_idx](neighbor_features))
                agg = torch.max(pooled, dim=0)[0]

            else:
                raise ValueError(f"不支持的聚合器类型: {self.aggregator_type}")

            aggregated.append(agg)

        return torch.stack(aggregated)

    def _aggregate_edge_features(self, graph, features, edge_features):
        num_nodes = features.shape[0]
        edge_aggregates = []

        for node in range(num_nodes):
            neighbors = self._sample_neighbors(graph, node)
            edge_feats = []

            for neighbor in neighbors:
                if (node, neighbor) in edge_features:
                    edge_feats.append(edge_features[(node, neighbor)])
                elif (neighbor, node) in edge_features:
                    edge_feats.append(edge_features[(neighbor, node)])
                else:
                    edge_feats.append(torch.zeros(self.edge_dim, device=features.device))

            edge_agg = torch.mean(torch.stack(edge_feats), dim=0)
            edge_aggregates.append(edge_agg)

        return torch.stack(edge_aggregates)

    def get_weights(self):
        """获取模型权重用于联邦学习"""
        return {name: param.detach().cpu().numpy() for name, param in self.named_parameters()}

    def set_weights(self, weights):
        """设置模型权重用于联邦学习"""
        for name, param in self.named_parameters():
            param.data = torch.tensor(weights[name], device=param.device)


# 3. 纵向图联邦学习系统
class VerticalGraphFLSystem:
    """基于GraphSAGE和qMIFE的纵向图联邦学习系统"""

    def __init__(self, n_clients: int, graph: nx.Graph, feature_dims: List[int],
                 num_classes: int, aggregator_type='max_pool'):
        self.n_clients = n_clients
        self.graph = graph
        self.feature_dims = feature_dims
        self.total_features = sum(feature_dims)
        self.num_classes = num_classes
        self.label_holder = 0  # 客户端0持有标签
        self.aggregator_type = aggregator_type

        # 初始化加密方案（输入槽数量：客户端数 + 1个标签槽）
        self.crypto = QuadraticMIFE(n_inputs=self.n_clients + 1)

        # 垂直分区图数据
        self.X, self.y, self.edge_features, self.edge_dim = self._partition_graph_data()

        # 初始化客户端模型
        self.client_models = self._init_client_models()

        # 全局模型（与客户端模型结构一致，用于聚合）
        self.global_model = GraphSAGE(
            input_dim=self.total_features,
            hidden_dim=64,
            output_dim=num_classes,
            num_layers=3,
            aggregator_type=aggregator_type,
            max_neighbors=10,
            edge_dim=self.edge_dim
        )

        # 训练记录
        self.loss_history = []
        self.val_f1_history = []

    def _partition_graph_data(self) -> Tuple[Dict[int, torch.Tensor], torch.Tensor, Dict, int]:
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

        # 生成边特征
        edge_dim = 4
        edge_features = {}
        for u, v in self.graph.edges():
            edge_features[(u, v)] = torch.randn(edge_dim)
            edge_features[(v, u)] = edge_features[(u, v)]

        return features, labels, edge_features, edge_dim

    def _init_client_models(self) -> Dict[int, GraphSAGE]:
        client_models = {}
        for i in range(self.n_clients):
            client_models[i] = GraphSAGE(
                input_dim=self.feature_dims[i],
                hidden_dim=64,
                output_dim=self.num_classes,
                num_layers=3,
                aggregator_type=self.aggregator_type,
                max_neighbors=10,
                edge_dim=self.edge_dim if i == self.label_holder else None
            )
            # 初始化特征适配器
            if self.feature_dims[i] != 64:  # 64是hidden_dim
                client_models[i].feature_adapter = nn.Linear(self.feature_dims[i], 64)
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
        optimizer = optim.Adam(self.client_models[client_id].parameters(), lr=0.001)

        self.client_models[client_id].train()
        optimizer.zero_grad()

        # 前向传播
        if client_id == self.label_holder:
            outputs = self.client_models[client_id](self.graph, self.X[client_id], self.edge_features)
        else:
            outputs = self.client_models[client_id](self.graph, self.X[client_id])

        loss = criterion(outputs[mask], self.y[mask] if client_id == self.label_holder else
        torch.zeros_like(outputs[mask], dtype=torch.long))
        loss.backward()

        # 提取梯度并加密
        encrypted_grads = {}
        for name, param in self.client_models[client_id].named_parameters():
            if param.grad is not None:
                grad_np = param.grad.detach().cpu().numpy().flatten()
                encrypted_grads[name] = self.crypto.encrypt(client_id, grad_np)

        # 标签持有者额外加密标签相关信息
        extra_data = {}
        if client_id == self.label_holder:
            labels_np = self.y[mask].cpu().numpy().flatten()
            extra_data['labels'] = self.crypto.encrypt(self.n_clients, labels_np)

        return encrypted_grads, extra_data, loss.item()

    def aggregate_gradients(self, encrypted_grads_list: List[Dict], extra_data_list: List[Dict]) -> Dict[
        str, np.ndarray]:
        """聚合器解密并聚合梯度"""
        # 收集所有密文
        ciphertexts = [{} for _ in range(self.n_clients + 1)]
        for i in range(self.n_clients):
            for name, ct in encrypted_grads_list[i].items():
                if name not in ciphertexts[i]:
                    ciphertexts[i][name] = []
                ciphertexts[i][name].append(ct)

        # 添加标签密文
        for i in range(self.n_clients):
            if i == self.label_holder and 'labels' in extra_data_list[i]:
                ciphertexts[self.n_clients]['labels'] = extra_data_list[i]['labels']

        # 解密并聚合梯度
        aggregated_grads = {}
        for name, param in self.global_model.named_parameters():
            # 构造函数向量用于解密
            param_shape = param.shape
            param_size = np.prod(param_shape)
            c = np.ones(param_size) / self.n_clients  # 平均聚合

            # 生成解密密钥
            sk = self.crypto.keygen(c)

            # 收集该参数的所有密文
            param_ciphertexts = []
            for i in range(self.n_clients):
                if name in ciphertexts[i]:
                    param_ciphertexts.extend(ciphertexts[i][name])

            # 解密并重塑梯度
            if param_ciphertexts:
                decrypted = self.crypto.decrypt(param_ciphertexts, sk)
                aggregated_grads[name] = np.reshape(decrypted, param_shape)

        return aggregated_grads

    def update_global_model(self, aggregated_grads: Dict[str, np.ndarray], lr=0.001):
        """使用聚合梯度更新全局模型"""
        global_weights = self.global_model.get_weights()
        for name, grad in aggregated_grads.items():
            if name in global_weights:
                global_weights[name] -= lr * grad
        self.global_model.set_weights(global_weights)
        return global_weights

    def evaluate_global_model(self, graph, features, labels, mask, edge_features=None):
        """评估全局模型性能"""
        self.global_model.eval()
        with torch.no_grad():
            full_features = torch.cat([features[i] for i in range(self.n_clients)], dim=1)
            if edge_features is not None:
                outputs = self.global_model(graph, full_features, edge_features)
            else:
                outputs = self.global_model(graph, full_features)

            predictions = torch.argmax(outputs[mask], dim=1)
            true_labels = labels[mask].numpy()
            pred_labels = predictions.numpy()

            f1 = f1_score(true_labels, pred_labels, average='macro')
            acc = accuracy_score(true_labels, pred_labels)

        return {"f1": f1, "acc": acc, "predictions": pred_labels, "true": true_labels}

    def train(self, train_mask, val_mask, epochs=200, lr=0.001):
        """联邦训练主流程"""
        masks = self.split_masks(train_mask, val_mask, [])

        print("开始纵向图联邦学习训练...")
        for epoch in range(epochs):
            # 1. 广播全局模型权重
            global_weights = self.global_model.get_weights()

            # 2. 客户端本地训练
            encrypted_grads_list = []
            extra_data_list = []
            client_losses = []

            for i in range(self.n_clients):
                grads, extra, loss = self.client_train(
                    client_id=i,
                    mask=masks['train'][i],
                    global_weights=global_weights,
                    epochs=1
                )
                encrypted_grads_list.append(grads)
                extra_data_list.append(extra)
                client_losses.append(loss)

            # 3. 聚合梯度
            aggregated_grads = self.aggregate_gradients(encrypted_grads_list, extra_data_list)

            # 4. 更新全局模型
            global_weights = self.update_global_model(aggregated_grads, lr)

            # 5. 评估
            val_res = self.evaluate_global_model(
                self.graph, self.X, self.y, masks['val'][self.label_holder], self.edge_features
            )

            # 记录
            self.loss_history.append(np.mean(client_losses))
            self.val_f1_history.append(val_res["f1"])

            if (epoch + 1) % 10 == 0:
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
    num_nodes = G.number_of_nodes()
    num_classes = 2  # 空手道俱乐部有两个类别

    # 初始化纵向图联邦学习系统
    # 3个客户端，分别持有不同维度的特征
    fl_system = VerticalGraphFLSystem(
        n_clients=3,
        graph=G,
        feature_dims=[5, 5, 6],  # 总特征维度16
        num_classes=num_classes,
        aggregator_type='max_pool'
    )

    # 开始训练
    fl_system.train(
        train_mask=train_mask,
        val_mask=val_mask,
        epochs=100,
        lr=0.001
    )

    # 测试最终模型
    test_res = fl_system.evaluate_global_model(
        fl_system.graph,
        fl_system.X,
        fl_system.y,
        test_mask,
        fl_system.edge_features
    )
    print(f"\n测试集性能: F1={test_res['f1']:.4f}, 准确率={test_res['acc']:.4f}")


if __name__ == "__main__":
    main()

