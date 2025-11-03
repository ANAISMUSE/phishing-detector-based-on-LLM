# app/utils/email_parser.py
import email
from email import policy
from email.parser import BytesParser
import re
from typing import Dict, List, Any

def parse_email(filepath: str) -> Dict[str, Any]:
    """
    解析邮件文件，提取关键信息
    
    Args:
        filepath: 邮件文件路径
        
    Returns:
        包含邮件信息的字典
    """
    try:
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        # 提取基本信息
        email_data = {
            'subject': msg.get('subject', ''),
            'from': msg.get('from', ''),
            'to': msg.get('to', ''),
            'date': msg.get('date', ''),
            'reply_to': msg.get('reply-to', ''),
            'return_path': msg.get('return-path', ''),
            'message_id': msg.get('message-id', ''),
        }
        
        # 提取正文内容
        body = extract_body(msg)
        email_data['body'] = body
        
        # 提取URLs
        urls = extract_urls(body)
        email_data['urls'] = urls
        
        # 提取所有头部
        email_data['headers'] = dict(msg.items())
        
        # 检查是否有附件
        email_data['has_attachments'] = has_attachments(msg)
        
        return email_data
        
    except Exception as e:
        raise Exception(f"解析邮件失败: {str(e)}")

def extract_body(msg) -> str:
    """提取邮件正文"""
    body = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                try:
                    body += part.get_content()
                except:
                    pass
            elif content_type == 'text/html':
                try:
                    html_content = part.get_content()
                    # 简单移除HTML标签
                    body += re.sub(r'<[^>]+>', '', html_content)
                except:
                    pass
    else:
        try:
            body = msg.get_content()
        except:
            body = str(msg.get_payload())
    
    return body

def extract_urls(text: str) -> List[str]:
    """从文本中提取URL"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return list(set(urls))  # 去重

def has_attachments(msg) -> bool:
    """检查是否有附件"""
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            return True
    return False
    