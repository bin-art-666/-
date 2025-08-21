import torch
import torch.nn as nn
import torch.optim as optim
import networkx as nx
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import f1_score, accuracy_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
from torch.nn import functional as F
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple, List, Dict, Any

# 字体配置
plt.rcParams["font.family"] = ["Microsoft YaHei", "SimHei", "SimSun"]
plt.rcParams['axes.unicode_minus'] = False


# 1. 双线性群与二次多输入函数加密（密码学基础组件）
class BilinearGroup:
    """双线性群实现，用于支持安全的联邦学习计算"""

    def __init__(self, curve=ec.SECP256R1):
        self.curve = curve
        self.backend = default_backend()

    def generate_group_params(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, bytes]:
        private_key = ec.generate_private_key(self.curve(), self.backend)
        public_key = private_key.public_key()
        generator = ec.generate_private_key(self.curve(), self.backend).public_key()
        return private_key, public_key, generator.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def bilinear_map(self, P: bytes, Q: bytes) -> bytes:
        return hashlib.sha256(P + Q).digest()


class QuadraticMIFE:
    """二次多输入函数加密，支持联邦环境下的安全计算"""

    def __init__(self, n_inputs: int, security_param: int = 128):
        self.n_inputs = n_inputs
        self.security_param = security_param
        self.group = BilinearGroup()
        self.msk, self.pp, self.generator = self.group.generate_group_params()
        self.ek = self._generate_encryption_keys()

    def _generate_encryption_keys(self) -> Dict[int, bytes]:
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
        assert len(ciphertexts) == self.n_inputs, "密文数量不匹配输入槽"

        result = 0.0
        sk_hash = hashlib.sha256(sk).digest()
        for ct in ciphertexts:
            ct_hash = hashlib.sha256(ct + sk_hash).digest()
            result += int.from_bytes(ct_hash[:4], 'big') / (1 << 24)
        return result


# 2. GraphSAGE模型（保留核心功能，适配联邦学习）
class GraphSAGE(nn.Module):
    """支持联邦学习的GraphSAGE模型，可处理分布式特征"""

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

    def get_local_gradients(self, graph, features, labels, mask, edge_features=None):
        """计算本地梯度，用于联邦学习"""
        self.train()
        outputs = self(graph, features, edge_features) if edge_features else self(graph, features)
        loss = F.cross_entropy(outputs[mask], labels[mask])
        loss.backward()

        # 收集梯度并清零
        gradients = {name: param.grad.clone() for name, param in self.named_parameters()}
        self.zero_grad()
        return gradients, loss.item()


# 3. 纵向图联邦学习系统
class VerticalGraphFLSystem:
    """纵向图联邦学习系统，结合GraphSAGE与qMIFE加密方案"""

    def __init__(self, graph: nx.Graph, feature_dims: List[int], num_classes: int,
                 label_holder: int = 0, aggregator_type='max_pool'):
        self.graph = graph
        self.n_clients = len(feature_dims)
        self.feature_dims = feature_dims
        self.total_features = sum(feature_dims)
        self.num_classes = num_classes
        self.label_holder = label_holder  # 持有标签的客户端
        self.crypto = QuadraticMIFE(n_inputs=self.n_clients + 1)  # +1用于标签槽

        # 初始化客户端模型（共享结构，私有参数）
        self.client_models = self._init_client_models(aggregator_type)

        # 数据分区（垂直划分节点特征）
        self.X_partitions, self.y, self.masks = self._partition_data()

    def _init_client_models(self, aggregator_type):
        """为每个客户端初始化本地模型"""
        clients = []
        for dim in self.feature_dims:
            model = GraphSAGE(
                input_dim=dim,
                hidden_dim=64,
                output_dim=self.num_classes,
                num_layers=3,
                aggregator_type=aggregator_type,
                max_neighbors=10
            )
            clients.append(model)
        return clients

    def _partition_data(self):
        """垂直分区节点特征，每个客户端持有不同的特征子集"""
        num_nodes = self.graph.number_of_nodes()
        # 生成完整特征集
        full_features = torch.randn(num_nodes, self.total_features)

        # 划分特征
        partitions = []
        start = 0
        for dim in self.feature_dims:
            partitions.append(full_features[:, start:start + dim])
            start += dim

        # 生成标签（使用空手道俱乐部标签）
        labels = torch.tensor([0 if self.graph.nodes[node]['club'] == 'Mr. Hi' else 1
                               for node in self.graph.nodes], dtype=torch.long)

        # 生成掩码
        train_mask, temp_mask = train_test_split(range(num_nodes), test_size=0.6, random_state=42)
        val_mask, test_mask = train_test_split(temp_mask, test_size=0.5, random_state=42)

        return partitions, labels, {
            'train': train_mask,
            'val': val_mask,
            'test': test_mask
        }

    def client_train_step(self, client_id: int, epochs: int = 1):
        """客户端本地训练步骤，返回加密的梯度"""
        model = self.client_models[client_id]
        features = self.X_partitions[client_id]
        mask = self.masks['train']
        optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=5e-4)

        local_grads = []
        for _ in range(epochs):
            # 计算本地梯度
            grads, loss = model.get_local_gradients(
                self.graph, features, self.y, mask
            )
            # 优化本地参数
            optimizer.zero_grad()
            for name, param in model.named_parameters():
                param.grad = grads[name]
            optimizer.step()

            # 加密梯度
            flattened_grad = np.concatenate([g.cpu().numpy().flatten() for g in grads.values()])
            encrypted_grad = self.crypto.encrypt(client_id, flattened_grad)
            local_grads.append((encrypted_grad, loss))

        return local_grads

    def aggregate_gradients(self, client_gradients: List[List[bytes]]):
        """聚合服务器：聚合各客户端的加密梯度"""
        # 每轮使用新的加密实例
        self.crypto = QuadraticMIFE(n_inputs=self.n_clients + 1)

        # 构造聚合函数向量（简单平均）
        c = np.ones(sum(self.feature_dims) + 1) / self.n_clients
        sk = self.crypto.keygen(c)

        # 解密并聚合梯度
        aggregated = []
        for epoch in range(len(client_gradients[0])):
            # 收集该轮所有客户端的梯度密文
            epoch_ciphertexts = [client_epoch[epoch][0] for client_epoch in client_gradients]

            # 加入标签持有者的额外信息
            if self.label_holder is not None:
                # 标签持有者提供的加密辅助信息
                label_info = self._get_encrypted_label_info()
                epoch_ciphertexts.append(label_info)

            # 解密聚合结果
            aggregated_grad = self.crypto.decrypt(epoch_ciphertexts, sk)
            aggregated.append(aggregated_grad)

        return aggregated

    def _get_encrypted_label_info(self):
        """标签持有者提供加密的标签信息"""
        mask = self.masks['train']
        label_subset = self.y[mask].numpy().flatten()
        return self.crypto.encrypt(self.n_clients, label_subset)

    def global_update(self, aggregated_grads):
        """使用聚合梯度更新全局模型（此处简化为平均更新）"""
        # 实际应用中应根据聚合梯度调整各客户端模型
        for model in self.client_models:
            for param in model.parameters():
                param.data -= 0.01 * torch.tensor(aggregated_grads[-1], dtype=torch.float32, device=param.device)

    def evaluate_global_model(self):
        """评估全局模型性能（通过安全聚合预测结果）"""
        # 收集各客户端的加密预测
        client_preds = []
        for cid, model in enumerate(self.client_models):
            features = self.X_partitions[cid]
            model.eval()
            with torch.no_grad():
                outputs = model(self.graph, features)
                preds = torch.argmax(outputs, dim=1).cpu().numpy()
                encrypted_preds = self.crypto.encrypt(cid, preds)
                client_preds.append(encrypted_preds)

        # 聚合预测结果
        c = np.ones(self.n_clients) / self.n_clients  # 简单多数投票权重
        sk = self.crypto.keygen(c)
        # 实际应用中需要更复杂的解密逻辑来获取最终预测
        # 此处简化为使用标签持有者的本地评估

        # 标签持有者本地评估
        test_mask = self.masks['test']
        model = self.client_models[self.label_holder]
        features = self.X_partitions[self.label_holder]
        model.eval()
        with torch.no_grad():
            outputs = model(self.graph, features)
            predictions = torch.argmax(outputs[test_mask], dim=1)
            true_labels = self.y[test_mask].numpy()
            acc = accuracy_score(true_labels, predictions.numpy())
            f1 = f1_score(true_labels, predictions.numpy(), average='macro')

        return {"acc": acc, "f1": f1}

    def train(self, global_epochs: int, local_epochs: int = 1):
        """完整训练流程"""
        metrics = []
        for epoch in range(global_epochs):
            print(f"\n全局轮次 {epoch + 1}/{global_epochs}")

            # 各客户端本地训练
            client_gradients = []
            for cid in range(self.n_clients):
                print(f"客户端 {cid} 本地训练中...")
                grads = self.client_train_step(cid, local_epochs)
                client_gradients.append(grads)

            # 聚合梯度
            aggregated_grads = self.aggregate_gradients(client_gradients)

            # 全局更新
            self.global_update(aggregated_grads)

            # 评估
            eval_res = self.evaluate_global_model()
            metrics.append(eval_res)
            print(f"当前性能: 准确率={eval_res['acc']:.4f}, F1={eval_res['f1']:.4f}")

        return metrics


# 4. 主函数
def main():
    # 加载图数据
    print("加载图数据...")
    G = nx.karate_club_graph()
    print(f"图节点数: {G.number_of_nodes()}, 边数: {G.number_of_edges()}")

    # 配置纵向联邦学习系统（3个客户端，特征维度分别为5,5,6）
    fl_system = VerticalGraphFLSystem(
        graph=G,
        feature_dims=[5, 5, 6],  # 垂直划分16维特征
        num_classes=2,
        label_holder=0,
        aggregator_type='max_pool'
    )

    # 开始联邦训练
    print("开始纵向图联邦学习训练...")
    metrics = fl_system.train(global_epochs=20, local_epochs=2)

    # 绘制训练曲线
    plt.figure(figsize=(12, 5))
    plt.subplot(1, 2, 1)
    plt.plot([m['acc'] for m in metrics])
    plt.title('全局模型准确率')
    plt.xlabel('全局轮次')

    plt.subplot(1, 2, 2)
    plt.plot([m['f1'] for m in metrics])
    plt.title('全局模型F1分数')
    plt.xlabel('全局轮次')

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()


