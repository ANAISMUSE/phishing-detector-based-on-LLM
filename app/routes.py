# app/routes.py
from flask import Blueprint, render_template, request, jsonify, current_app
import os
from werkzeug.utils import secure_filename
from app.utils.email_parser import parse_email
from app.utils.analyzer import analyze_email

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/analyze', methods=['POST'])
def analyze():
    """分析上传的邮件"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': '没有上传文件'}), 400
        
        file = request.files['file']
        
        if not file.filename or file.filename == '':
            return jsonify({'success': False, 'error': '未选择文件'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': '不支持的文件格式'}), 400
        
        # 保存文件
        original_filename = file.filename
        if original_filename is None:
            return jsonify({'success': False, 'error': '文件名无效'}), 400
            
        filename = secure_filename(original_filename)
        if not filename:
            filename = 'uploaded_file.eml'
        
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # ========== 这里才是真正调用LLM ==========
        try:
            # 1. 解析邮件
            email_data = parse_email(filepath)
            
            # 2. 使用LLM分析
            result = analyze_email(email_data)
            
        except Exception as e:
            result = {
                'success': False,
                'error': f'分析失败: {str(e)}'
            }
        # ==========================================
        
        # 删除临时文件
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            print(f"删除临时文件失败: {e}")
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"处理错误: {str(e)}")
        return jsonify({'success': False, 'error': f'处理失败: {str(e)}'}), 500

def allowed_file(filename: str | None) -> bool:
    if filename is None:
        return False
    ALLOWED_EXTENSIONS = {'eml', 'msg', 'txt'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
