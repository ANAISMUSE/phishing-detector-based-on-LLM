FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 创建上传目录
RUN mkdir -p /app/uploads && chmod 777 /app/uploads

# 暴露端口
EXPOSE 5000

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=run.py

# 生产模式使用 gunicorn（run.py 中 app = create_app()）
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "run:app"]
