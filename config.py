# config.py
import os

class Config:
    """应用配置类"""
    
    # 基础配置
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-please-change')
    
    # 文件上传配置
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'eml', 'msg', 'txt'}
    
    # API配置
    DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY', '')
    DEEPSEEK_API_BASE = os.environ.get('DEEPSEEK_API_BASE', 'https://api.deepseek.com')
    
    # 模型配置
    MODEL_NAME = 'deepseek-chat'
    MAX_TOKENS = 2000
    TEMPERATURE = 0.7
    
    @staticmethod
    def init_app(app):
        """初始化应用配置"""
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
