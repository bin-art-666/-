import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from matplotlib.patches import Rectangle, Circle, Arrow
import matplotlib.patheffects as path_effects

plt.figure(figsize=(12, 8), facecolor='#f0f8ff')
ax = plt.axes(xlim=(-1, 11), ylim=(-1, 7))
ax.set_facecolor('#f0f8ff')
ax.set_axis_off()
plt.title('私钥与公钥工作原理可视化', fontsize=16, pad=20)

# 创建主要元素
alice_box = Rectangle((0.5, 2), 3, 3, facecolor='#ffebee', edgecolor='#d32f2f', linewidth=2)
bob_box = Rectangle((6.5, 2), 3, 3, facecolor='#e3f2fd', edgecolor='#1976d2', linewidth=2)
ax.add_patch(alice_box)
ax.add_patch(bob_box)

plt.text(2, 5.5, "Alice", fontsize=14, ha='center', color='#d32f2f')
plt.text(8, 5.5, "Bob", fontsize=14, ha='center', color='#1976d2')

# 创建密钥元素
private_key = Circle((2, 3.5), 0.4, facecolor='gold', edgecolor='#d32f2f', linewidth=2)
public_key = Circle((8, 3.5), 0.4, facecolor='#bbdefb', edgecolor='#1976d2', linewidth=2)
ax.add_patch(private_key)
ax.add_patch(public_key)

plt.text(2, 3.5, "私钥", fontsize=10, ha='center', va='center')
plt.text(8, 3.5, "公钥", fontsize=10, ha='center', va='center')

# 创建消息
message = Rectangle((3.5, 4), 2, 0.5, facecolor='#c8e6c9', edgecolor='#388e3c', linewidth=1)
ax.add_patch(message)
message_text = plt.text(4.5, 4.25, "秘密消息", fontsize=10, ha='center', va='center', color='#1b5e20')

# 创建锁元素
lock = Rectangle((4.5, 3), 0.8, 0.8, facecolor='#bdbdbd', edgecolor='#424242', linewidth=1)
ax.add_patch(lock)

# 创建加密/解密说明
encrypt_text = plt.text(2, 1.2, "", fontsize=12, ha='center', color='#d32f2f',
                        path_effects=[path_effects.withStroke(linewidth=2, foreground='white')])
decrypt_text = plt.text(8, 1.2, "", fontsize=12, ha='center', color='#1976d2',
                        path_effects=[path_effects.withStroke(linewidth=2, foreground='white')])


# 动画函数
def animate(frame):
    # 清除之前的箭头
    for art in ax.artists:
        if isinstance(art, Arrow):
            art.remove()

    # 分阶段动画
    if frame < 30:  # 阶段1：Alice创建密钥对
        progress = frame / 30
        encrypt_text.set_text(f"Alice 生成密钥对\n{int(progress * 100)}%")

        # 显示密钥生成过程
        if frame == 15:
            key_link = Arrow(2, 3.5, 6, 0, width=0.1, color='#7b1fa2', alpha=0.5)
            ax.add_patch(key_link)
            plt.text(5, 3.7, "数学关联", fontsize=9, ha='center', color='#7b1fa2')

    elif frame < 60:  # 阶段2：Alice发送公钥给Bob
        progress = (frame - 30) / 30
        encrypt_text.set_text(f"Alice 发送公钥给 Bob\n{int(progress * 100)}%")

        # 移动公钥的动画
        if frame < 45:
            x_pos = 2 + (8 - 2) * ((frame - 30) / 15)
            public_key.center = (x_pos, 3.5)

        # 显示传输箭头
        if frame > 35:
            arrow = Arrow(2, 3.2, 6, 0, width=0.1, color='#1976d2')
            ax.add_patch(arrow)

    elif frame < 90:  # 阶段3：Bob用公钥加密消息
        progress = (frame - 60) / 30
        decrypt_text.set_text(f"Bob 用公钥加密消息\n{int(progress * 100)}%")

        # 显示加密过程
        if frame > 70:
            arrow = Arrow(8, 3.2, -3.5, 0.8, width=0.1, color='#1976d2')
            ax.add_patch(arrow)
            lock.set_facecolor('#ffcc80')  # 锁变成金色表示加密

    elif frame < 120:  # 阶段4：Bob发送加密消息
        progress = (frame - 90) / 30
        decrypt_text.set_text(f"Bob 发送加密消息\n{int(progress * 100)}%")

        # 移动消息的动画
        if frame < 105:
            x_pos = 4.5 + (4.5 - 4.5) * ((frame - 90) / 15)
            y_pos = 4.25 - (4.25 - 1.5) * ((frame - 90) / 15)
            message.set_xy([x_pos - 1, y_pos - 0.25])
            message_text.set_position((x_pos, y_pos))
            lock.set_xy([x_pos - 0.4, y_pos - 0.4])

        # 显示传输箭头
        if frame > 95:
            arrow = Arrow(4.5, 1.5, -4, 1.5, width=0.1, color='#388e3c')
            ax.add_patch(arrow)

    elif frame < 150:  # 阶段5：Alice用私钥解密
        progress = (frame - 120) / 30
        encrypt_text.set_text(f"Alice 用私钥解密\n{int(progress * 100)}%")

        # 显示解密过程
        if frame > 130:
            arrow = Arrow(2, 3.2, 1.5, 0.8, width=0.1, color='#d32f2f')
            ax.add_patch(arrow)
            lock.set_facecolor('#c8e6c9')  # 锁变成绿色表示解密

    else:  # 阶段6：完成
        encrypt_text.set_text("完成！只有Alice能解密")
        decrypt_text.set_text("因为只有她有私钥")

        # 显示最终消息位置
        message.set_xy([1.5, 4 - 0.25])
        message_text.set_position((2.5, 4.25))
        lock.set_xy([1.6, 4 - 0.4])

        # 添加庆祝元素
        if frame % 10 < 5:
            for i in range(5):
                x = 2 + np.cos(i * 2 * np.pi / 5)
                y = 4.5 + np.sin(i * 2 * np.pi / 5)
                star = plt.scatter(x, y, s=50, c='gold', marker='*', alpha=0.8)

    return private_key, public_key, message, message_text, lock, encrypt_text, decrypt_text


# 创建动画
anim = FuncAnimation(plt.gcf(), animate, frames=180, interval=50, blit=False)

plt.tight_layout()
plt.show()