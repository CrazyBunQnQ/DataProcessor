import cv2
import os

# RTSP URL
rtsp_url = 'rtsp://192.168.3.157'

# Load the Haar Cascade Classifier for face detection
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

# Output directory to save face images
output_dir = 'detected_faces'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Function to detect faces in a frame and save face images
def detect_and_save_faces(frame, frame_count):
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

    for i, (x, y, w, h) in enumerate(faces):
        face_roi = frame[y:y+h, x:x+w]
        face_filename = f'face_{frame_count}_{i}.jpg'
        cv2.imwrite(os.path.join(output_dir, face_filename), face_roi)
        cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)

    return frame

# Connect to the RTSP camera
cap = cv2.VideoCapture(rtsp_url)

if not cap.isOpened():
    print("Error: Could not open RTSP stream.")
    exit()

frame_count = 0

# Read and process frames from the camera
while True:
    ret, frame = cap.read()
    if not ret:
        print("Error: Failed to capture frame from camera.")
        break

    # Detect faces in the frame and save face images
    frame_with_faces = detect_and_save_faces(frame, frame_count)
    frame_count += 1

    # Display the frame with detected faces
    cv2.imshow('Face Detection', frame_with_faces)

    # Exit loop when 'q' is pressed
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

# Release the capture and close all OpenCV windows
cap.release()
cv2.destroyAllWindows()
