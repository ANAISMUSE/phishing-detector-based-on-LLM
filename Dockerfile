FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 创建上传目录
RUN mkdir -p /app/uploads && chmod 777 /app/uploads

# 下载NLTK数据
RUN python -m nltk.downloader punkt stopwords

# 暴露端口
EXPOSE 5000

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=run.py
ENV FLASK_ENV=production

# 运行应用
CMD ["python", "run.py"]
