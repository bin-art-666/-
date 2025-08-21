from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# 生成密钥对
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# 要签名的消息（使用encode转为字节串）
message = "向B转账1000元".encode('utf-8')  # 关键修改：添加encode()

print("=== 发送方操作 ===")
# 1. 创建签名
signature = private_key.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)
print(f"生成签名: {signature.hex()[:20]}...")

print("\n=== 接收方操作 ===")
# 2. 验证签名
try:
    public_key.verify(
        signature,
        message,
        ec.ECDSA(hashes.SHA256())
    )
    print("✅ 签名有效！消息真实且未被篡改")
except InvalidSignature:
    print("❌ 签名无效！消息可能被篡改或来源可疑")

# 模拟攻击者篡改消息
print("\n=== 攻击者篡改消息 ===")
tampered_message = "向C转账10000元".encode('utf-8')  # 同样添加encode()

try:
    public_key.verify(
        signature,
        tampered_message,  # 使用篡改后的消息
        ec.ECDSA(hashes.SHA256())
    )
    print("❌ 错误：篡改后验证仍通过")
except InvalidSignature:
    print("✅ 成功检测到消息篡改！")