#!/bin/bash

# 确保脚本可执行
# chmod +x run.sh

# 检查Docker是否安装
if ! [ -x "$(command -v docker)" ]; then
  echo 'Error: Docker is not installed.' >&2
  exit 1
fi

# 设置API密钥（可以从环境变量或配置文件读取）
if [ -z "$DEEPSEEK_API_KEY" ]; then
  echo "警告: DEEPSEEK_API_KEY 环境变量未设置!"
  echo "请设置您的API密钥:"
  read -s DEEPSEEK_API_KEY
fi

# 构建Docker镜像
echo "Building Docker image..."
docker build -t phishing-detector .

# 运行容器
echo "Starting container..."
docker run -d \
  --name phishing-detector-app \
  -p 5000:5000 \
  -e DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY \
  phishing-detector

# 检查容器是否成功启动
if [ "$(docker ps -q -f name=phishing-detector-app)" ]; then
  echo "Container started successfully."
  echo "Application is running at http://localhost:5000"
else
  echo "Container failed to start. Check logs with: docker logs phishing-detector-app"
  exit 1
fi
