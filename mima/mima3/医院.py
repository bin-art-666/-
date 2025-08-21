from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
import matplotlib.pyplot as plt
import matplotlib as mpl

# 添加以下配置
plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei']  # 中文支持
plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题


class PatientDataSystem:
    """保护患者隐私的医疗数据分析系统"""

    def __init__(self, security_param=256):
        self.security_param = security_param
        self.mpk, self.msk = self.setup()
        self.patient_data = {}

    def setup(self):
        """初始化系统，生成主密钥"""
        # 在实际系统中会使用更安全的加密方案
        msk = os.urandom(self.security_param)  # 主私钥
        mpk = hashes.Hash(hashes.SHA256(), backend=default_backend())
        mpk.update(msk)
        mpk = mpk.finalize()  # 主公钥
        return mpk, msk

    def key_gen(self, func_type):
        """为特定分析函数生成函数密钥"""
        # 在真实系统中，函数密钥需要严格授权管理
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"Medical_FE_Key",
            info=func_type.encode(),
            backend=default_backend()
        )
        return hkdf.derive(self.msk)

    def add_patient(self, patient_id, data):
        """添加患者数据（已加密存储）"""
        # 患者数据结构: [年龄, 血型编码, 身高, 体重, 疾病编码, 治疗费用]
        encrypted_data = self.encrypt(data)
        self.patient_data[patient_id] = encrypted_data

    def encrypt(self, plain_data):
        """加密患者数据"""
        # 将数据转换为字节串
        data_bytes = b"".join([str(val).encode() for val in plain_data])

        # 使用HKDF派生加密密钥
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"Patient_Data_Encryption",
            info=data_bytes,
            backend=default_backend()
        )
        return hkdf.derive(self.mpk)

    def analyze_age_disease(self, sk_F, patient_ids):
        """使用函数密钥分析年龄与疾病关系"""
        # 收集加密的患者数据
        encrypted_samples = [self.patient_data[pid] for pid in patient_ids]

        # 使用函数密钥"解密"获得分析结果
        # 在实际系统中，这里会执行特定的数学计算
        results = []
        for ct in encrypted_samples:
            # 模拟函数计算：只提取年龄和疾病信息
            h = hmac.HMAC(sk_F, hashes.SHA256(), backend=default_backend())
            h.update(ct)
            result_digest = h.finalize()

            # 从摘要中提取年龄和疾病信息（模拟）
            age = int.from_bytes(result_digest[:2], 'big') % 100  # 年龄0-99
            disease = int.from_bytes(result_digest[2:3], 'big') % 10  # 疾病编码0-9
            results.append((age, disease))

        return results


def visualize_analysis(results):
    """可视化年龄与疾病关系"""
    ages, diseases = zip(*results)

    # 创建DataFrame
    df = pd.DataFrame({
        'Age': ages,
        'Disease': diseases
    })

    # 按年龄分组统计疾病分布
    age_groups = pd.cut(df['Age'], bins=range(0, 101, 10))
    disease_by_age = df.groupby([age_groups, 'Disease'], observed=False).size().unstack().fillna(0)


    # 绘制图表
    plt.figure(figsize=(12, 6))

    # 疾病随年龄分布
    plt.subplot(1, 2, 1)
    disease_by_age.plot(kind='bar', stacked=True, ax=plt.gca())
    plt.title('疾病分布随年龄变化')
    plt.xlabel('年龄组')
    plt.ylabel('患者数量')
    plt.legend(title='疾病类型', bbox_to_anchor=(1.05, 1), loc='upper left')

    # 线性回归分析
    plt.subplot(1, 2, 2)
    plt.scatter(ages, diseases, alpha=0.6)

    # 添加回归线
    X = np.array(ages).reshape(-1, 1)
    y = np.array(diseases)
    model = LinearRegression().fit(X, y)
    plt.plot(X, model.predict(X), color='red', linewidth=2)

    plt.title('年龄与疾病相关性')
    plt.xlabel('年龄')
    plt.ylabel('疾病严重程度')
    plt.grid(True)

    plt.tight_layout()
    plt.show()

    # 返回分析结果
    return {
        'total_patients': len(results),
        'age_disease_correlation': model.coef_[0],
        'disease_distribution': disease_by_age.to_dict()
    }


# ========== 示例使用 ==========
if __name__ == "__main__":
    print("=" * 50)
    print("保护隐私的医疗数据分析系统")
    print("=" * 50)

    # 创建医疗数据系统
    hospital_system = PatientDataSystem()

    # 添加模拟患者数据 (ID, [年龄, 血型, 身高(cm), 体重(kg), 疾病编码, 治疗费用(万元)])
    patients = [
        (101, [35, 2, 175, 70, 3, 5.2]),
        (102, [28, 1, 168, 65, 1, 3.8]),
        (103, [45, 3, 182, 85, 5, 12.5]),
        (104, [62, 4, 170, 78, 7, 8.9]),
        (105, [50, 2, 165, 60, 4, 6.7]),
        (106, [39, 1, 180, 92, 6, 15.3]),
        (107, [71, 4, 172, 68, 8, 9.8]),
        (108, [55, 3, 178, 80, 5, 11.2]),
        (109, [42, 2, 163, 58, 3, 4.5]),
        (110, [31, 1, 185, 95, 2, 7.1]),
        (111, [67, 4, 169, 72, 9, 18.6]),
        (112, [48, 3, 176, 83, 6, 13.4]),
        (113, [53, 2, 171, 75, 4, 8.2]),
        (114, [37, 1, 167, 63, 2, 5.9]),
        (115, [59, 4, 173, 79, 7, 10.7])
    ]

    for pid, data in patients:
        hospital_system.add_patient(pid, data)
    print(f"已加密存储 {len(patients)} 名患者数据")

    # 研究机构申请分析权限
    research_key = hospital_system.key_gen("age_disease_analysis")
    print("研究机构获得年龄-疾病分析函数密钥")

    # 分析所有患者数据（不暴露敏感信息）
    patient_ids = [pid for pid, _ in patients]
    analysis_results = hospital_system.analyze_age_disease(research_key, patient_ids)

    print("\n分析结果:")
    print(f"样本数量: {len(analysis_results)}")
    print("前5个样本结果:")
    for i, (age, disease) in enumerate(analysis_results[:5]):
        print(f"  样本 {i + 1}: 年龄={age}, 疾病编码={disease}")

    # 可视化分析结果
    print("\n生成分析报告...")
    report = visualize_analysis(analysis_results)

    print("\n关键发现:")
    print(f"年龄与疾病相关性系数: {report['age_disease_correlation']:.4f}")
    print("各年龄段疾病分布:")
    for age_group, diseases in report['disease_distribution'].items():
        print(f"  {age_group}: {diseases}")