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


# 1. 双线性群与二次多输入函数加密
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
    """改进的二次多输入函数加密"""

    def __init__(self, n_inputs: int, security_param: int = 128):
        self.n_inputs = n_inputs
        self.security_param = security_param
        self.group = BilinearGroup()
        self.msk, self.pp, self.generator = self.group.generate_group_params()
        self.ek = self._generate_encryption_keys()
        self.scale_factor = 1 << 16  # 更精细的量化尺度

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
            result += int.from_bytes(ct_hash[:4], 'big') / self.scale_factor
        return result / len(ciphertexts)  # 均值化降低波动


# 2. GraphSAGE模型（添加稳定采样）
class GraphSAGE(nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim, num_layers=3,
                 aggregator_type='max_pool', max_neighbors=10, edge_dim=None):
        super().__init__()
        self.num_layers = num_layers
        self.aggregator_type = aggregator_type
        self.max_neighbors = max_neighbors
        self.edge_dim = edge_dim
        self.hidden_dim = hidden_dim
        self.input_dim = input_dim
        self.current_epoch = 0  # 新增：记录当前轮次

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

    def set_epoch(self, epoch):
        """设置当前训练轮次"""
        self.current_epoch = epoch

    def _sample_neighbors(self, graph, node):
        """稳定采样实现"""
        seed = hash(f"{node}_{self.current_epoch}") % (2 ** 32)
        np.random.seed(seed)

        neighbors = list(graph.neighbors(node))
        if len(neighbors) > self.max_neighbors:
            neighbors = sorted(neighbors)[:self.max_neighbors]  # 确定性选择
        elif len(neighbors) < self.max_neighbors:
            neighbors = neighbors + [node] * (self.max_neighbors - len(neighbors))
        return neighbors

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
        self.train()
        outputs = self(graph, features, edge_features) if edge_features else self(graph, features)
        loss = F.cross_entropy(outputs[mask], labels[mask])
        loss.backward()

        gradients = {name: param.grad.clone() for name, param in self.named_parameters()}
        self.zero_grad()
        return gradients, loss.item()


# 3. 纵向图联邦学习系统
class VerticalGraphFLSystem:
    def __init__(self, graph: nx.Graph, feature_dims: List[int], num_classes: int,
                 label_holder: int = 0, aggregator_type='max_pool'):
        self.graph = graph
        self.n_clients = len(feature_dims)
        self.feature_dims = feature_dims
        self.total_features = sum(feature_dims)
        self.num_classes = num_classes
        self.label_holder = label_holder
        self.crypto = QuadraticMIFE(n_inputs=self.n_clients + 1)
        self.client_models = self._init_client_models(aggregator_type)
        self.X_partitions, self.y, self.masks = self._partition_data()
        self.metrics_history = []
        self.confusion_matrices = []
        self.client_loss_history = []  # 新增：记录客户端损失历史

    def _init_client_models(self, aggregator_type):
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
        num_nodes = self.graph.number_of_nodes()
        full_features = torch.randn(num_nodes, self.total_features)

        partitions = []
        start = 0
        for dim in self.feature_dims:
            partitions.append(full_features[:, start:start + dim])
            start += dim

        labels = torch.tensor([0 if self.graph.nodes[node]['club'] == 'Mr. Hi' else 1
                               for node in self.graph.nodes], dtype=torch.long)

        train_mask, temp_mask = train_test_split(range(num_nodes), test_size=0.6, random_state=42)
        val_mask, test_mask = train_test_split(temp_mask, test_size=0.5, random_state=42)

        return partitions, labels, {
            'train': train_mask,
            'val': val_mask,
            'test': test_mask
        }

    def _calculate_client_weights(self) -> List[float]:
        """动态权重计算"""
        if not hasattr(self, 'client_loss_history') or len(self.client_loss_history) < 3:
            total_dim = sum(self.feature_dims)
            return [dim / total_dim for dim in self.feature_dims]
        else:
            avg_losses = [np.mean(history[-3:]) for history in self.client_loss_history]
            weights = 1 / (np.array(avg_losses) + 1e-8)
            return (weights / weights.sum()).tolist()

    def client_train_step(self, client_id: int, epochs: int = 1):
        model = self.client_models[client_id]
        features = self.X_partitions[client_id]
        mask = self.masks['train']
        optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=5e-4)

        local_grads = []
        for _ in range(epochs):
            grads, loss = model.get_local_gradients(self.graph, features, self.y, mask)
            optimizer.zero_grad()
            for name, param in model.named_parameters():
                param.grad = grads[name]
            optimizer.step()

            flattened_grad = np.concatenate([g.cpu().numpy().flatten() for g in grads.values()])
            encrypted_grad = self.crypto.encrypt(client_id, flattened_grad)
            local_grads.append((encrypted_grad, loss))
        return local_grads

    def aggregate_gradients(self, client_gradients: List[List[bytes]]):
        self.crypto = QuadraticMIFE(n_inputs=self.n_clients + 1)
        self.client_loss_history = [
            [epoch[1] for epoch in client]
            for client in client_gradients
        ]

        weights = self._calculate_client_weights()
        c_parts = []
        for weight, dim in zip(weights, self.feature_dims):
            c_parts.append(np.ones(dim) * weight)
        c = np.concatenate(c_parts)

        if self.label_holder is not None:
            c = np.concatenate([c, [1.0]])

        c /= np.sum(c)
        sk = self.crypto.keygen(c)

        aggregated_grads = []
        aggregated_losses = []
        for epoch in range(len(client_gradients[0])):
            epoch_ciphertexts = [client_epoch[epoch][0] for client_epoch in client_gradients]
            epoch_losses = [client_epoch[epoch][1] for client_epoch in client_gradients]

            if self.label_holder is not None:
                label_info = self._get_encrypted_label_info()
                epoch_ciphertexts.append(label_info)

            aggregated_grad = self.crypto.decrypt(epoch_ciphertexts, sk)
            aggregated_grads.append(aggregated_grad)
            aggregated_losses.append(np.mean(epoch_losses))

        return aggregated_grads, aggregated_losses

    def _get_encrypted_label_info(self):
        mask = self.masks['train']
        label_subset = self.y[mask].numpy().flatten()
        return self.crypto.encrypt(self.n_clients, label_subset)

    def global_update(self, aggregated_grads):
        global_grad = torch.tensor(aggregated_grads[-1], dtype=torch.float32)
        for i, model in enumerate(self.client_models):
            lr = 0.01 * (self.feature_dims[i] / max(self.feature_dims))
            for param in model.parameters():
                param.data -= lr * global_grad.to(param.device)

    def evaluate_global_model(self):
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
            cm = confusion_matrix(true_labels, predictions.numpy())
            loss = F.cross_entropy(outputs[test_mask], self.y[test_mask]).item()

        return {
            "acc": acc,
            "f1": f1,
            "loss": loss,
            "confusion_matrix": cm
        }

    def train(self, global_epochs: int, local_epochs: int = 1):
        for epoch in range(global_epochs):
            print(f"\n全局轮次 {epoch + 1}/{global_epochs}")

            for model in self.client_models:
                model.set_epoch(epoch)

            client_gradients = []
            for cid in range(self.n_clients):
                print(f"客户端 {cid} 本地训练中...")
                grads = self.client_train_step(cid, local_epochs)
                client_gradients.append(grads)

            aggregated_grads, aggregated_losses = self.aggregate_gradients(client_gradients)
            self.global_update(aggregated_grads)

            eval_res = self.evaluate_global_model()
            self.metrics_history.append(eval_res)
            self.confusion_matrices.append(eval_res["confusion_matrix"])

            print(f"当前性能: 准确率={eval_res['acc']:.4f}, F1={eval_res['f1']:.4f}, 损失={eval_res['loss']:.4f}")
            print("混淆矩阵:")
            print(eval_res["confusion_matrix"])

        return self.metrics_history, self.confusion_matrices


# 4. 主函数
def main():
    print("加载图数据...")
    G = nx.karate_club_graph()
    print(f"图节点数: {G.number_of_nodes()}, 边数: {G.number_of_edges()}")

    fl_system = VerticalGraphFLSystem(
        graph=G,
        feature_dims=[5, 5, 6],
        num_classes=2,
        label_holder=0,
        aggregator_type='max_pool'
    )

    print("开始纵向图联邦学习训练...")
    metrics, cms = fl_system.train(global_epochs=20, local_epochs=2)

    plt.figure(figsize=(18, 10))
    plt.subplot(2, 2, 1)
    plt.plot([m['acc'] for m in metrics])
    plt.title('全局模型准确率')
    plt.xlabel('全局轮次')
    plt.ylim(0, 1)

    plt.subplot(2, 2, 2)
    plt.plot([m['f1'] for m in metrics])
    plt.title('全局模型F1分数')
    plt.xlabel('全局轮次')
    plt.ylim(0, 1)

    plt.subplot(2, 2, 3)
    plt.plot([m['loss'] for m in metrics])
    plt.title('全局模型损失值')
    plt.xlabel('全局轮次')

    plt.subplot(2, 2, 4)
    final_cm = cms[-1]
    im = plt.imshow(final_cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('最终混淆矩阵')
    plt.colorbar(im)

    classes = [f'类别 {i}' for i in range(final_cm.shape[0])]
    plt.xticks(range(final_cm.shape[1]), classes)
    plt.yticks(range(final_cm.shape[0]), classes)

    thresh = final_cm.max() / 2.
    for i in range(final_cm.shape[0]):
        for j in range(final_cm.shape[1]):
            plt.text(j, i, format(final_cm[i, j], 'd'),
                     horizontalalignment="center",
                     color="white" if final_cm[i, j] > thresh else "black")

    plt.ylabel('真实标签')
    plt.xlabel('预测标签')
    plt.tight_layout()
    plt.show()

    print("\n最终模型评估报告:")
    final_metrics = metrics[-1]
    print(f"准确率: {final_metrics['acc']:.4f}")
    print(f"F1分数: {final_metrics['f1']:.4f}")
    print(f"损失值: {final_metrics['loss']:.4f}")
    print("混淆矩阵:")
    print(final_metrics['confusion_matrix'])
    print("\n分类报告:")
    test_mask = fl_system.masks['test']
    true_labels = fl_system.y[test_mask].numpy()
    model = fl_system.client_models[fl_system.label_holder]
    features = fl_system.X_partitions[fl_system.label_holder]
    model.eval()
    with torch.no_grad():
        outputs = model(fl_system.graph, features)
        predictions = torch.argmax(outputs[test_mask], dim=1).numpy()
    print(classification_report(true_labels, predictions))


if __name__ == "__main__":
    main()
