import datetime
import os

import cv2
import face_recognition
import torch
import torchvision.transforms as transforms
from PIL import Image

# 确保 detected_faces 目录存在
output_dir = 'detected_faces'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# 连接 RTSP 流
rtsp_url = 'rtsp://192.168.3.157'
cap = cv2.VideoCapture(rtsp_url)

# 定义图像转换
preprocess = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
])

# 使用预训练的 ResNet50 模型
model = torch.hub.load('pytorch/vision:v0.10.0', 'resnet50', pretrained=True)
model.eval()

frame_count = 0

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        print("无法接收帧 (stream end?). Exiting ...")
        break

    # 使用 face_recognition 检测人脸位置
    face_locations = face_recognition.face_locations(frame)

    for i, (top, right, bottom, left) in enumerate(face_locations):
        # 提取人脸区域
        face_img = frame[top:bottom, left:right]

        # 转换为 PIL Image
        pil_img = Image.fromarray(face_img)

        # 预处理图像
        input_tensor = preprocess(pil_img)
        input_batch = input_tensor.unsqueeze(0)

        # 如果有可用的 GPU，则将模型和数据移到 GPU 上
        if torch.cuda.is_available():
            input_batch = input_batch.to('cuda')
            model.to('cuda')

        with torch.no_grad():
            output = model(input_batch)

        # 获取模型预测的分类结果
        _, predicted = torch.max(output, 1)

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
