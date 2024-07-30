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
rtsp_url = 'rtsp://192.168.3.159'
cap = cv2.VideoCapture(rtsp_url)
# 设置缓冲区大小
cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
# 设置帧率
# desired_fps = 25  # 修改为你想要的帧率
# cap.set(cv2.CAP_PROP_FPS, desired_fps)

# 初始化 MTCNN 模型
mtcnn = MTCNN(keep_all=True, device='cuda' if torch.cuda.is_available() else 'cpu')

frame_count = 0
# 节省性能, 每多少帧处理一次
process_every_n_frames = 3

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        print("无法接收帧 (stream end?). Exiting ...")
        break
    frame_count += 1
    if frame_count % process_every_n_frames != 0:
        continue

    # 将帧旋转180°
    # frame = cv2.rotate(frame, cv2.ROTATE_180)

    # pretime = datetime.datetime.now()
    # 使用 MTCNN 检测人脸
    boxes, _ = mtcnn.detect(frame)

    if boxes is not None:
        for i, box in enumerate(boxes):
            # 提取人脸区域
            left, top, right, bottom = map(int, box)
            face_img = frame[top:bottom, left:right]
            # 分辨率低于 40*40 则忽略
            if face_img.shape[0] < 35 or face_img.shape[1] < 35:
                continue

            # 生成文件名并保存
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            face_filename = os.path.join(output_dir, f"face_{timestamp}_{i}.jpg")
            cv2.imwrite(face_filename, face_img)
            print(f"保存人脸图片到: {face_filename}")

            # 在图像上绘制矩形框
            cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 0), 2)
        # current_time = datetime.datetime.now()
        # 统计用时
        # print(f"用时: {current_time - pretime}")

    # 显示实时监测窗口
    cv2.imshow('Real-time Face Detection', frame)

    # 监听键盘事件，按下 q 键退出
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

    # pretime = datetime.datetime.now()

# 释放资源
cap.release()
cv2.destroyAllWindows()
