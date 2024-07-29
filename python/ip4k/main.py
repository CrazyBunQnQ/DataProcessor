import datetime
import os

import cv2
import torch
from facenet_pytorch import MTCNN

# 确保 detected_faces 目录存在
output_dir = 'detected_faces'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# 连接 RTSP 流
rtsp_url = 'rtsp://192.168.3.157'
cap = cv2.VideoCapture(rtsp_url)
# 设置缓冲区大小
cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

# 初始化 MTCNN 模型
mtcnn = MTCNN(keep_all=True, device='cuda' if torch.cuda.is_available() else 'cpu')

frame_count = 0

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        print("无法接收帧 (stream end?). Exiting ...")
        break

    # 使用 MTCNN 检测人脸
    boxes, _ = mtcnn.detect(frame)

    if boxes is not None:
        for i, box in enumerate(boxes):
            # 提取人脸区域
            left, top, right, bottom = map(int, box)
            face_img = frame[top:bottom, left:right]

            # 生成文件名并保存
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            face_filename = os.path.join(output_dir, f"face_{timestamp}_{frame_count}_{i}.jpg")
            cv2.imwrite(face_filename, face_img)
            print(f"保存人脸图片到: {face_filename}")

            # 在图像上绘制矩形框
            cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 0), 2)

    # 显示实时监测窗口
    cv2.imshow('Real-time Face Detection', frame)

    # 监听键盘事件，按下 q 键退出
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

    frame_count += 1

# 释放资源
cap.release()
cv2.destroyAllWindows()
