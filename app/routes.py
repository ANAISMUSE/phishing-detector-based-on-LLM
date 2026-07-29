# app/routes.py
from flask import Blueprint, render_template, request, jsonify, current_app
import os
from werkzeug.utils import secure_filename

from app.utils.email_parser import parse_email, parse_email_string
from app.utils.engine import run_analysis
from app.utils.detection import deepseek_llm_call

main_bp = Blueprint('main', __name__)


def _make_llm_func():
    """根据配置构造 LLM 调用函数；缺 key 时返回 None（仅规则模式）。"""
    api_key = current_app.config.get('DEEPSEEK_API_KEY', '')
    if not api_key:
        return None
    model = current_app.config.get('MODEL_NAME', 'deepseek-chat')
    api_base = current_app.config.get('DEEPSEEK_API_BASE', 'https://api.deepseek.com')

    def _call(prompt: str) -> str:
        return deepseek_llm_call(prompt, api_key, model, api_base)

    return _call


@main_bp.route('/')
def index():
    return render_template('index.html')


@main_bp.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'phishing-detector'}), 200


@main_bp.route('/analyze', methods=['POST'])
def analyze():
    """文件上传分析（前端 AJAX 入口）。"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': '没有上传文件'}), 400

        file = request.files['file']
        if not file.filename or file.filename == '':
            return jsonify({'success': False, 'error': '未选择文件'}), 400
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': '不支持的文件格式'}), 400

        original_filename = file.filename
        filename = secure_filename(original_filename) or 'uploaded_file.eml'
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            email_data = parse_email(filepath)
            result = run_analysis(email_data, _make_llm_func())
        except Exception as e:
            result = {'success': False, 'error': f'分析失败: {str(e)}'}
        finally:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception:
                pass

        if result.get('success') is False:
            return jsonify(result), 500
        return jsonify(result), 200

    except Exception as e:
        return jsonify({'success': False, 'error': f'处理失败: {str(e)}'}), 500


@main_bp.route('/api/v1/analyze', methods=['POST'])
def api_analyze():
    """REST API：接收原始邮件（raw RFC822 文本或 base64 编码的 .eml）。"""
    try:
        payload = request.get_json(silent=True) or {}
        raw = payload.get('email') or payload.get('eml')
        if not raw:
            return jsonify({'success': False, 'error': 'JSON 字段 "email" 缺失'}), 400

        # 支持 base64 编码的 .eml 附件
        if payload.get('encoding') == 'base64':
            import base64
            try:
                raw = base64.b64decode(raw).decode('utf-8', 'replace')
            except Exception:
                return jsonify({'success': False, 'error': 'base64 解码失败'}), 400

        email_data = parse_email_string(raw)
        result = run_analysis(email_data, _make_llm_func())
        if result.get('success') is False:
            return jsonify(result), 500
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'success': False, 'error': f'处理失败: {str(e)}'}), 500


def allowed_file(filename: str | None) -> bool:
    if filename is None:
        return False
    ALLOWED_EXTENSIONS = {'eml', 'msg', 'txt'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
