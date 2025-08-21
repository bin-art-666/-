import hashlib
import os
import logging
import numpy as np
import matplotlib.pyplot as plt
import networkx as nx
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, f1_score, confusion_matrix,
                             classification_report)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from typing import Dict, Tuple, List, Any, Optional

# 字体配置
plt.rcParams["font.family"] = ["Microsoft YaHei", "SimHei", "SimSun"]
plt.rcParams['axes.unicode_minus'] = False

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("fl_training.log"), logging.StreamHandler()]
)

# 设备配置
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
logging.info(f"使用设备: {DEVICE}")


# 1. 加密模块：双线性群与二次多输入函数加密
class BilinearGroup:
    """基于椭圆曲线的双线性群实现，修复曲线阶数访问问题"""
    
    def __init__(self, curve=ec.SECP256R1):
        # 曲线类（如SECP256R1）
        self.curve_class = curve
        # 后端
        self.backend = default_backend()
        
        # 生成临时私钥获取曲线实例
        temp_private_key = ec.generate_private_key(self.curve_class, self.backend)
        self.curve = temp_private_key.curve
        
        # SECP256R1的已知阶数（硬编码解决版本兼容问题）
        self.order = 115792089210356248762697446949407573529996955224135760342422259061068512044369
        
        # 生成双线性群的生成元
        self.g1 = ec.generate_private_key(self.curve_class, self.backend).public_key()
        self.g2 = ec.generate_private_key(self.curve_class, self.backend).public_key()

    def multiply(self, point: ec.EllipticCurvePublicKey, scalar: int) -> ec.EllipticCurvePublicKey:
        """椭圆曲线点乘：k * P"""
        if not isinstance(scalar, int):
            raise ValueError("标量必须为整数")
        
        public_numbers = point.public_numbers()
        multiplied_numbers = public_numbers.multiply(scalar)
        return multiplied_numbers.public_key(self.backend)

    def bilinear_map(self, p: ec.EllipticCurvePublicKey, q: ec.EllipticCurvePublicKey) -> bytes:
        """双线性映射模拟"""
        p_bytes = p.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        q_bytes = q.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return hashlib.sha256(p_bytes + q_bytes).digest()

    def generate_private_key(self) -> ec.EllipticCurvePrivateKey:
        """生成当前曲线的私钥"""
        return ec.generate_private_key(self.curve_class, self.backend)

    def get_public_key(self, private_key: ec.EllipticCurvePrivateKey) -> ec.EllipticCurvePublicKey:
        """从私钥获取公钥"""
        return private_key.public_key()


class QuadraticMIFE:
    """改进的二次多输入函数加密（支持向量加密）"""
    def __init__(self, n_inputs: int, security_param: int = 128):
        self.n_inputs = n_inputs
        self.security_param = security_param
        self.group = BilinearGroup()
        self.msk = self.group.generate_private_key()  # 主私钥
        self.pp = self.group.get_public_key(self.msk)  # 公共参数（主公钥）
        self.ek = self._generate_encryption_keys()  # 加密密钥字典
        self.scale_factor = 1 << 16  # 量化尺度，用于浮点数转整数

    def _generate_encryption_keys(self) -> Dict[int, ec.EllipticCurvePrivateKey]:
        """生成每个输入方的加密密钥对"""
        ek = {}
        for i in range(self.n_inputs):
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=f"qMIFE_enc_key_{i}".encode(),
                backend=default_backend()
            )
            derived = hkdf.derive(self.msk.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            priv_num = int.from_bytes(derived, byteorder='big') % self.group.order
            ek[i] = ec.derive_private_key(
                priv_num,
                self.group.curve_class(),
                self.group.backend
            )
        return ek

    def encrypt(self, input_index: int, x: np.ndarray) -> List[bytes]:
        """加密向量x（输入方input_index的本地数据）"""
        assert input_index < self.n_inputs, "输入索引无效"
        assert len(x.shape) == 1, "输入必须为1D向量"

        sk_i = self.ek[input_index]
        pk_i = self.group.get_public_key(sk_i)
        ciphertexts = []

        for val in x:
            quantized = int(val * self.scale_factor)
            hx = self.group.multiply(pk_i, quantized)
            r = np.random.randint(1, self.group.order)
            gr = self.group.multiply(self.group.g1, r)
            
            hx_bytes = hx.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            gr_bytes = gr.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            ciphertext = gr_bytes + hx_bytes
            ciphertexts.append(ciphertext)

        return ciphertexts

    def keygen(self, c: np.ndarray) -> bytes:
        """生成函数密钥（基于系数向量c）"""
        assert len(c.shape) == 1, "系数向量必须为1D"
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"qMIFE_func_key",
            backend=default_backend()
        )
        return hkdf.derive(
            self.msk.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ) + c.tobytes()
        )

    def decrypt(self, ciphertexts: List[List[bytes]], sk: bytes) -> np.ndarray:
        """解密聚合结果"""
        assert len(ciphertexts) == self.n_inputs, "密文数量不匹配输入数"
        dim = len(ciphertexts[0])  # 向量维度
        result = np.zeros(dim, dtype=np.float32)

        for i in range(dim):
            sum_val = 0
            for j in range(self.n_inputs):
                ct = ciphertexts[j][i]
                gr_bytes = ct[:65]
                hx_bytes = ct[65:]

                gr = serialization.load_der_public_key(gr_bytes, self.group.backend)
                hx = serialization.load_der_public_key(hx_bytes, self.group.backend)

                pair_val = self.group.bilinear_map(hx, gr)
                hash_val = hashlib.sha256(pair_val + sk).digest()
                sum_val += int.from_bytes(hash_val[:4], 'big', signed=True)

            result[i] = sum_val / self.scale_factor / self.n_inputs

        return result


# 2. 图神经网络模型：改进的GraphSAGE
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
        self.current_epoch = 0  # 用于稳定采样的当前轮次
        self.client_models = None  # 后续绑定的客户端模型列表

        # 网络层
        self.layers = nn.ModuleList()
        self.norms = nn.ModuleList()
        self.aggregator_layers = nn.ModuleList()

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

        # 输出层（中间特征）
        in_channels = hidden_dim * 2
        if edge_dim is not None:
            in_channels += edge_dim
        self.layers.append(nn.Linear(in_channels, output_dim))

        # 聚合器专用层
        if aggregator_type == 'max_pool':
            for i in range(num_layers):
                in_dim = input_dim if i == 0 else hidden_dim
                self.aggregator_layers.append(nn.Linear(in_dim, hidden_dim))
        elif aggregator_type == 'attn':
            for i in range(num_layers):
                in_dim = input_dim if i == 0 else hidden_dim
                self.aggregator_layers.append(nn.Linear(in_dim * 2, 1))

        self.activation = nn.ReLU()
        self.dropout = nn.Dropout(0.5)
        self.to(DEVICE)

    def set_epoch(self, epoch):
        """设置当前训练轮次（用于稳定采样）"""
        self.current_epoch = epoch

    def _sample_neighbors(self, graph, node):
        """改进的节点采样：基于度数的加权采样"""
        np.random.seed(seed=hash((node, self.current_epoch, os.getpid())) % (2 **32))
        neighbors = list(graph.neighbors(node))
        if not neighbors:
            return [node] * self.max_neighbors
        
        degrees = [graph.degree(n) for n in neighbors]
        total_degree = sum(degrees)
        probs = np.array(degrees) / total_degree if total_degree > 0 else None
        
        if len(neighbors) >= self.max_neighbors:
            sampled = np.random.choice(neighbors, size=self.max_neighbors, replace=False, p=probs)
        else:
            sampled = neighbors + [node] * (self.max_neighbors - len(neighbors))
        return list(sampled)

    def forward(self, graph, features, edge_features=None):
        """前向传播（修复残差连接）"""
        x = features.to(DEVICE)
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
        """特征聚合"""
        num_nodes = features.shape[0]
        neighbors_list = [self._sample_neighbors(graph, node) for node in range(num_nodes)]
        
        neighbor_indices = torch.tensor(neighbors_list, dtype=torch.long, device=DEVICE)
        neighbor_features = features[neighbor_indices]  # [N, K, D]

        if self.aggregator_type == 'mean':
            agg = torch.mean(neighbor_features, dim=1)
        elif self.aggregator_type == 'max_pool':
            pooled = self.activation(self.aggregator_layers[layer_idx](neighbor_features))
            agg = torch.max(pooled, dim=1)[0]
        elif self.aggregator_type == 'attn':
            node_feat = features.unsqueeze(1).repeat(1, self.max_neighbors, 1)
            attn_input = torch.cat([node_feat, neighbor_features], dim=2)
            attn_weights = F.softmax(self.aggregator_layers[layer_idx](attn_input), dim=1)
            agg = torch.sum(attn_weights * neighbor_features, dim=1)
        else:
            raise ValueError(f"不支持的聚合器类型: {self.aggregator_type}")

        return agg

    def _aggregate_edge_features(self, graph, features, edge_features):
        """边特征聚合"""
        num_nodes = features.shape[0]
        edge_aggregates = []

        for node in range(num_nodes):
            neighbors = self._sample_neighbors(graph, node)
            edge_feats = []
            weights = []
            
            for neighbor in neighbors:
                if (node, neighbor) in edge_features:
                    ef = edge_features[(node, neighbor)]
                    w = graph[node][neighbor].get('weight', 1.0)
                elif (neighbor, node) in edge_features:
                    ef = edge_features[(neighbor, node)]
                    w = graph[neighbor][node].get('weight', 1.0)
                else:
                    ef = torch.zeros(self.edge_dim, device=DEVICE)
                    w = 1.0
                edge_feats.append(ef)
                weights.append(w)
            
            weights = torch.tensor(weights, device=DEVICE).unsqueeze(1)
            edge_feats = torch.stack(edge_feats)
            weighted_avg = torch.sum(weights * edge_feats, dim=0) / torch.sum(weights)
            edge_aggregates.append(weighted_avg)
        
        return torch.stack(edge_aggregates)

    def get_local_gradients(self, graph, features, labels, mask, all_intermediates, classifier=None):
        """获取本地梯度（接收所有客户端的中间特征）"""
        self.train()
        features = features.to(DEVICE)
        labels = labels.to(DEVICE) if labels is not None else None
        mask = torch.tensor(mask, device=DEVICE)

        # 生成当前客户端的中间特征
        intermediate = self(graph, features)
        all_intermediates.append(intermediate)  # 收集当前客户端的中间特征

        # 仅标签持有方计算损失和梯度（此时all_intermediates已收集所有客户端特征）
        if classifier is not None and labels is not None and self.client_models is not None and len(all_intermediates) == len(self.client_models):
            # 拼接所有客户端的中间特征
            fused = torch.cat(all_intermediates, dim=1)
            outputs = classifier(fused)
            loss = F.cross_entropy(outputs[mask], labels[mask])
            loss.backward()

            gradients = {name: param.grad.clone() for name, param in self.named_parameters() if param.grad is not None}
            self.zero_grad()
            return gradients, loss.item(), intermediate.detach()
        else:
            return None, 0.0, intermediate.detach()


# 3. 纵向图联邦学习系统
class VerticalGraphFLSystem:
    def __init__(self, graph: nx.Graph, feature_dims: List[int], num_classes: int,
                 label_holder: int = 0, aggregator_type='max_pool', intermediate_dim=32):
        self.graph = graph
        self.n_clients = len(feature_dims)
        self.feature_dims = feature_dims
        self.num_classes = num_classes
        self.label_holder = label_holder
        self.intermediate_dim = intermediate_dim
        
        # 加密模块
        self.crypto = QuadraticMIFE(n_inputs=self.n_clients)
        
        # 初始化模型
        self.client_models = self._init_client_models(aggregator_type)
        # 给每个模型绑定客户端数量（用于梯度计算）
        for model in self.client_models:
            model.client_models = self.client_models
        
        self.global_classifier = self._init_classifier()
        
        # 数据分区
        self.X_partitions, self.y, self.masks = self._partition_data()
        
        # 训练记录
        self.metrics_history = []
        self.confusion_matrices = []
        self.client_loss_history = [[] for _ in range(self.n_clients)]
        self.param_shapes = self._get_param_shapes()

    def _init_client_models(self, aggregator_type):
        """初始化客户端模型"""
        clients = []
        for dim in self.feature_dims:
            model = GraphSAGE(
                input_dim=dim,
                hidden_dim=64,
                output_dim=self.intermediate_dim,
                num_layers=3,
                aggregator_type=aggregator_type,
                max_neighbors=10
            )
            clients.append(model)
        return clients

    def _init_classifier(self):
        """初始化全局分类器（输入维度为所有客户端中间特征之和）"""
        return nn.Sequential(
            nn.Linear(self.intermediate_dim * self.n_clients, 64),  # 32*3=96
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(64, self.num_classes)
        ).to(DEVICE)

    def _partition_data(self):
        """数据分区（特征分片）"""
        num_nodes = self.graph.number_of_nodes()
        
        # 生成特征（结合图属性与随机特征）
        degrees = np.array([self.graph.degree(node) for node in range(num_nodes)]).reshape(-1, 1)
        clustering = np.array([nx.clustering(self.graph, node) for node in range(num_nodes)]).reshape(-1, 1)
        base_features = np.hstack([degrees, clustering])
        rand_features = np.random.randn(num_nodes, self.total_features - base_features.shape[1])
        full_features = np.hstack([base_features, rand_features])
        full_features = torch.tensor(full_features, dtype=torch.float32)

        # 特征分片
        partitions = []
        start = 0
        for dim in self.feature_dims:
            partitions.append(full_features[:, start:start + dim])
            start += dim

        # 标签（空手道俱乐部数据集）
        labels = torch.tensor([
            0 if self.graph.nodes[node]['club'] == 'Mr. Hi' else 1
            for node in self.graph.nodes
        ], dtype=torch.long)

        # 划分训练/验证/测试集
        train_mask, temp_mask = train_test_split(range(num_nodes), test_size=0.6, random_state=42)
        val_mask, test_mask = train_test_split(temp_mask, test_size=0.5, random_state=42)

        return partitions, labels, {
            'train': train_mask,
            'val': val_mask,
            'test': test_mask
        }

    @property
    def total_features(self):
        return sum(self.feature_dims)

    def _get_param_shapes(self):
        """记录参数形状用于梯度分配"""
        param_info = []
        for model in self.client_models:
            shapes = {}
            total_len = 0
            for name, param in model.named_parameters():
                shape = param.shape
                numel = param.numel()
                shapes[name] = (shape, total_len, total_len + numel)
                total_len += numel
            param_info.append({'shapes': shapes, 'total_len': total_len})
        return param_info

    def _calculate_client_weights(self) -> List[float]:
        """计算客户端权重（基于损失和特征维度）"""
        if len(self.client_loss_history[0]) < 3:
            total_dim = sum(self.feature_dims)
            return [dim / total_dim for dim in self.feature_dims]
        else:
            avg_losses = [np.mean(history[-3:]) for history in self.client_loss_history]
            weights = 1 / (np.array(avg_losses) + 1e-8)
            return (weights / weights.sum()).tolist()

    def client_train_step(self, client_id: int, epochs: int = 1):
        """客户端本地训练步骤（收集所有客户端中间特征）"""
        model = self.client_models[client_id]
        features = self.X_partitions[client_id]
        mask = self.masks['train']
        optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=5e-4)
        is_label_holder = (client_id == self.label_holder)

        local_grads = []
        for _ in range(epochs):
            # 收集所有客户端的中间特征
            all_intermediates = []
            if is_label_holder:
                # 标签持有方需要先获取所有客户端的中间特征
                for cid in range(self.n_clients):
                    client_model = self.client_models[cid]
                    client_features = self.X_partitions[cid]
                    # 生成其他客户端的中间特征（无梯度计算）
                    client_model.eval()
                    with torch.no_grad():
                        intermediate = client_model(self.graph, client_features)
                    all_intermediates.append(intermediate)
                
                # 计算当前客户端的梯度（使用所有中间特征）
                grads, loss, _ = model.get_local_gradients(
                    self.graph, features, self.y, mask,
                    all_intermediates=all_intermediates,
                    classifier=self.global_classifier
                )
                
                # 仅在获取有效梯度时执行更新（关键修复）
                if grads is not None:
                    # 本地更新
                    optimizer.zero_grad()
                    for name, param in model.named_parameters():
                        if name in grads:
                            param.grad = grads[name]
                    optimizer.step()
                    # 记录并加密梯度
                    self.client_loss_history[client_id].append(loss)
                    flattened_grad = np.concatenate([
                        g.cpu().numpy().flatten() for g in grads.values()
                    ])
                    encrypted_grad = self.crypto.encrypt(client_id, flattened_grad)
                    local_grads.append((encrypted_grad, loss))
                else:
                    # 无有效梯度时记录默认损失
                    local_grads.append((None, 0.0))
            else:
                # 非标签持有方：仅生成中间特征（不计算梯度）
                _, loss, _ = model.get_local_gradients(
                    self.graph, features, self.y, mask,
                    all_intermediates=[],  # 非标签持有方不收集其他特征
                    classifier=None
                )
                local_grads.append((None, loss))

        return local_grads

    def aggregate_gradients(self, client_gradients: List[List[Any]]):
        """聚合梯度"""
        label_holder_id = self.label_holder
        valid_ciphertexts = []
        for cid in range(self.n_clients):
            if cid == label_holder_id:
                epoch_ciphers = [client_epoch[0] for client_epoch in client_gradients[cid] if client_epoch[0] is not None]
                valid_ciphertexts.append(epoch_ciphers)

        if not valid_ciphertexts or len(valid_ciphertexts[0]) == 0:
            logging.warning("没有可聚合的有效梯度")
            return [], []

        # 生成聚合密钥
        weights = self._calculate_client_weights()
        c = np.array(weights)
        sk = self.crypto.keygen(c)

        # 解密并聚合
        aggregated_grads = []
        for epoch in range(len(valid_ciphertexts[0])):
            epoch_ciphertexts = [ct_list[epoch] for ct_list in valid_ciphertexts]
            decrypted = self.crypto.decrypt(epoch_ciphertexts, sk)
            aggregated_grads.append(decrypted)

        # 聚合损失
        aggregated_losses = []
        for epoch in range(len(client_gradients[0])):
            epoch_losses = [client_epoch[epoch][1] for client_epoch in client_gradients if client_epoch[epoch][1] is not None]
            if epoch_losses:
                aggregated_losses.append(np.mean(epoch_losses))

        return aggregated_grads, aggregated_losses

    def global_update(self, aggregated_grads):
        """全局更新模型"""
        if not aggregated_grads:
            logging.warning("没有有效梯度用于全局更新")
            return
            
        latest_grad = aggregated_grads[-1]
        label_holder_id = self.label_holder
        model = self.client_models[label_holder_id]
        param_info = self.param_shapes[label_holder_id]

        # 自适应学习率
        avg_loss = np.mean(self.client_loss_history[label_holder_id][-3:]) if len(
            self.client_loss_history[label_holder_id]) >=3 else 1.0
        lr = 0.01 * (1 / (avg_loss + 1e-8))

        # 更新客户端模型
        for name, param in model.named_parameters():
            if name in param_info['shapes']:
                shape, start, end = param_info['shapes'][name]
                grad_slice = latest_grad[start:end].reshape(shape)
                param.data -= lr * torch.tensor(grad_slice, dtype=torch.float32, device=DEVICE)

        # 更新分类器
        optimizer = optim.Adam(self.global_classifier.parameters(), lr=lr)
        optimizer.zero_grad()
        optimizer.step()

    def evaluate_global_model(self):
        """评估全局模型"""
        test_mask = self.masks['test']
        test_mask_tensor = torch.tensor(test_mask, device=DEVICE)
        all_intermediates = []

        # 收集所有客户端中间特征
        for cid in range(self.n_clients):
            model = self.client_models[cid]
            features = self.X_partitions[cid].to(DEVICE)
            model.eval()
            with torch.no_grad():
                intermediate = model(self.graph, features)
                all_intermediates.append(intermediate[test_mask_tensor])

        # 融合特征并预测（正确拼接所有客户端特征）
        fused = torch.cat(all_intermediates, dim=1)
        outputs = self.global_classifier(fused)
        predictions = torch.argmax(outputs, dim=1)
        true_labels = self.y[test_mask_tensor].cpu().numpy()
        predictions_np = predictions.cpu().numpy()

        # 计算指标
        acc = accuracy_score(true_labels, predictions_np)
        f1_macro = f1_score(true_labels, predictions_np, average='macro')
        f1_micro = f1_score(true_labels, predictions_np, average='micro')
        f1_weighted = f1_score(true_labels, predictions_np, average='weighted')
        loss = F.cross_entropy(outputs, self.y[test_mask_tensor]).item()
        cm = confusion_matrix(true_labels, predictions_np)

        return {
            "acc": acc,
            "f1_macro": f1_macro,
            "f1_micro": f1_micro,
            "f1_weighted": f1_weighted,
            "loss": loss,
            "confusion_matrix": cm
        }

    def train(self, global_epochs: int, local_epochs: int = 1):
        """联邦训练主流程"""
        for epoch in range(global_epochs):
            logging.info(f"\n全局轮次 {epoch + 1}/{global_epochs}")

            # 设置当前轮次（用于稳定采样）
            for model in self.client_models:
                model.set_epoch(epoch)

            # 客户端本地训练
            client_gradients = []
            for cid in range(self.n_clients):
                logging.info(f"客户端 {cid} 本地训练中...")
                grads = self.client_train_step(cid, local_epochs)
                client_gradients.append(grads)

            # 聚合梯度
            aggregated_grads, aggregated_losses = self.aggregate_gradients(client_gradients)
            if aggregated_losses:
                logging.info(f"第{epoch+1}轮聚合损失: {np.mean(aggregated_losses):.4f}")
            else:
                logging.warning("第{epoch+1}轮没有有效的聚合损失")

            # 全局更新
            self.global_update(aggregated_grads)

            # 评估
            eval_res = self.evaluate_global_model()
            self.metrics_history.append(eval_res)
            self.confusion_matrices.append(eval_res["confusion_matrix"])

            logging.info(
                f"当前性能: 准确率={eval_res['acc']:.4f}, "
                f"宏F1={eval_res['f1_macro']:.4f}, "
                f"损失={eval_res['loss']:.4f}"
            )

        return self.metrics_history, self.confusion_matrices


# 4. 主函数
def main():
    logging.info("加载图数据...")
    G = nx.karate_club_graph()
    # 添加边权重
    for u, v in G.edges():
        G[u][v]['weight'] = np.random.uniform(0.5, 1.5)
    logging.info(f"图节点数: {G.number_of_nodes()}, 边数: {G.number_of_edges()}")

    # 初始化联邦系统
    fl_system = VerticalGraphFLSystem(
        graph=G,
        feature_dims=[5, 5, 6],  # 三个客户端的特征维度
        num_classes=2,
        label_holder=0,  # 客户端0为标签持有方
        aggregator_type='max_pool',
        intermediate_dim=32
    )

    # 开始训练
    logging.info("开始纵向图联邦学习训练...")
    metrics, cms = fl_system.train(global_epochs=20, local_epochs=2)

    # 可视化结果
    plt.figure(figsize=(18, 15))

    plt.subplot(3, 2, 1)
    plt.plot([m['acc'] for m in metrics])
    plt.title('全局模型准确率')
    plt.xlabel('全局轮次')
    plt.ylim(0, 1)

    plt.subplot(3, 2, 2)
    plt.plot([m['f1_macro'] for m in metrics], label='宏F1')
    plt.plot([m['f1_micro'] for m in metrics], label='微F1')
    plt.title('F1分数对比')
    plt.xlabel('全局轮次')
    plt.ylim(0, 1)
    plt.legend()

    plt.subplot(3, 2, 3)
    plt.plot([m['loss'] for m in metrics])
    plt.title('全局模型损失值')
    plt.xlabel('全局轮次')

    plt.subplot(3, 2, 4)
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
    plt.savefig('fl_results.png')
    plt.show()

    # 输出最终结果
    logging.info("\n最终模型评估报告:")
    final_metrics = metrics[-1]
    logging.info(f"准确率: {final_metrics['acc']:.4f}")
    logging.info(f"宏F1: {final_metrics['f1_macro']:.4f}")
    logging.info(f"微F1: {final_metrics['f1_micro']:.4f}")
    logging.info(f"加权F1: {final_metrics['f1_weighted']:.4f}")
    logging.info(f"损失: {final_metrics['loss']:.4f}")


if __name__ == "__main__":
    main()
    